import json
import logging

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.darkweb.models import ScanResult
from apps.darkweb.services import DarkWebService, analyze, get_provider
from apps.darkweb.services.threat_intel_client import ThreatIntelClient
from apps.darkweb.stats import get_dashboard_stats, CACHE_KEY

logger = logging.getLogger(__name__)


def _get_service() -> DarkWebService | None:
    logger.debug("[DarkWeb] _get_service() called")
    provider = get_provider()
    if provider is None:
        logger.warning("[DarkWeb] No provider available from get_provider()")
        return None
    logger.debug("[DarkWeb] Provider obtained: %s", type(provider).__name__)
    return DarkWebService(provider=provider)


def _make_ti_client(request):
    host = request.get_host()
    url = f"http://{host}/api/threat-intel/"
    return ThreatIntelClient(endpoint_url=url)


def _save_scan(query: str, asset_type: str, data: dict) -> ScanResult:
    risk_score = 0
    breach_count = 0
    total_records = 0

    if "risk_score" in data:
        risk_score = data["risk_score"]
        breach_count = data.get("breach_count", 0)
    elif "risk" in data:
        risk_score = data["risk"].get("score", 0)
        breach_count = len(data.get("breaches", []))
        total_records = data.get("total_records_exposed", 0)

    logger.info("[DarkWeb] Saving scan: query=%s, type=%s, risk=%d, breaches=%d, records=%s",
                query, asset_type, risk_score, breach_count, f"{total_records:,}")

    result = ScanResult.objects.create(
        query=query,
        asset_type=asset_type,
        risk_score=risk_score,
        breach_count=breach_count,
        total_records_exposed=total_records,
        response_data=data,
    )
    cache.delete(CACHE_KEY)
    return result


def index(request):
    stats = get_dashboard_stats()
    if settings.DEBUG:
        logger.debug("[DarkWeb] Index page loaded. Stats: %s", stats)
    return render(request, "pages/darkweb/index.html", {
        "stats": stats,
    })


@require_http_methods(["GET"])
def analyze_view(request):
    query = request.GET.get("q", "").strip()
    asset_type = request.GET.get("type") or None

    logger.info("[DarkWeb] analyze_view called: q=%s, type=%s", query, asset_type)

    if not query:
        logger.warning("[DarkWeb] Empty query parameter")
        return JsonResponse({"success": False, "error": "Please provide a search query (email, phone, domain, or username)."}, status=400)

    hibp_key = getattr(settings, "HIBP_API_KEY", "")
    logger.info("[DarkWeb] HIBP_API_KEY configured: %s", "YES" if hibp_key else "NO")

    try:
        result = analyze(query, asset_type=asset_type)
        result_success = result.get("success", False)
        result_error = result.get("error")

        logger.info("[DarkWeb] analyze complete: success=%s, error=%s", result_success, result_error)

        if result_error:
            logger.warning("[DarkWeb] analyze returned error: %s", result_error)

        if result_success:
            _save_scan(result["query"], result["type"], result["data"])

            ti_client = _make_ti_client(request)
            result["data"]["related_intel"] = ti_client.extract_related_intel(
                result["query"], result["type"]
            )

        return JsonResponse(result, safe=False)
    except Exception as e:
        logger.exception(f"[DarkWeb] analyze_view exception for query: {query}")
        return JsonResponse({"success": False, "error": "An internal error occurred during analysis. Please try again."}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def scan_view(request):
    try:
        body = json.loads(request.body) if request.body else {}
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON body."}, status=400)

    asset = (body.get("asset") or "").strip()
    asset_type = body.get("asset_type") or None
    logger.info("[DarkWeb] scan_view called: asset=%s, type=%s", asset, asset_type)

    if not asset:
        return JsonResponse({"success": False, "error": "Asset is required."}, status=400)

    try:
        service = _get_service()
        if service is None:
            logger.warning("[DarkWeb] scan_view: no service available")
            return JsonResponse({
                "success": False,
                "error": "Breach data source not configured. Set a HaveIBeenPwned API key to enable scanning.",
            }, status=503)

        result = service.scan(asset, asset_type=asset_type)
        if result.get("success", True):
            _save_scan(result["asset"], result["asset_type"], result)
            ti_client = _make_ti_client(request)
            result["related_intel"] = ti_client.extract_related_intel(
                result["asset"], result["asset_type"]
            )

        return JsonResponse(result, safe=False)
    except Exception as e:
        logger.exception(f"[DarkWeb] scan_view exception for asset: {asset}")
        return JsonResponse({"success": False, "error": "An internal error occurred during the scan."}, status=500)


@require_http_methods(["GET"])
def stats_view(request):
    return JsonResponse(get_dashboard_stats())
