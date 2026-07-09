import json
import logging

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

logger = logging.getLogger(__name__)


@require_http_methods(["POST"])
@csrf_exempt
def browser_isolation_view_api(request):
    try:
        data = json.loads(request.body)
        url = data.get("url", "").strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    if not url:
        return JsonResponse({"error": "URL is required"}, status=400)

    if not url.startswith("http"):
        url = "https://" + url

    try:
        from apps.browser_isolation.scanner import BrowserIsolationScanner
        scanner = BrowserIsolationScanner(url)
        result = scanner.scan()
        if result.get("error"):
            return JsonResponse(result, status=400)
        return JsonResponse(result)
    except Exception as e:
        logger.exception("Browser isolation scan failed for %s", url)
        return JsonResponse({"error": f"Internal error: {str(e)}"}, status=500)
