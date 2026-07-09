import json
import logging
import time

from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.dns_lookup.scanner import run_dns_lookup

logger = logging.getLogger(__name__)

RATE_LIMIT_KEY_PREFIX = "dns_lookup_rate:"
RATE_LIMIT_SECONDS = 5


def _get_client_ip(request):
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def _check_rate_limit(key):
    if cache.get(key):
        return False
    cache.set(key, True, RATE_LIMIT_SECONDS)
    return True


@csrf_exempt
@require_http_methods(["POST"])
def dns_lookup_view_api(request):
    try:
        body = json.loads(request.body)
        target = (body.get("target") or "").strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({"success": False, "error": "Invalid JSON payload."}, status=400)

    if not target:
        return JsonResponse({"success": False, "error": "Please enter a domain name to look up."}, status=400)

    client_ip = _get_client_ip(request)
    rate_key = f"{RATE_LIMIT_KEY_PREFIX}{client_ip}"
    if not _check_rate_limit(rate_key):
        return JsonResponse(
            {"success": False, "error": "Rate limit: please wait 5 seconds between lookups."},
            status=429,
        )

    scan_start = time.time()
    try:
        results = run_dns_lookup(target)
    except Exception as e:
        logger.exception("DNS lookup failed for target: %s", target)
        return JsonResponse({"success": False, "error": f"Lookup failed: {str(e)[:200]}"}, status=500)

    elapsed = round((time.time() - scan_start) * 1000, 1)
    results["scan_time_ms"] = elapsed

    return JsonResponse(results)
