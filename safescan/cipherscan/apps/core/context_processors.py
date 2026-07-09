from django.conf import settings
from django.urls import reverse_lazy


def site_settings(request):
    return {
        "SITE_NAME": getattr(settings, "SITE_NAME", "CipherScan"),
        "SITE_TAGLINE": "Analyze. Detect. Protect.",
        "CURRENT_YEAR": 2026,
        "SCAN_TOOLS_URL": "/browser-isolation/",
        "SCAN_DETAIL_URL": reverse_lazy("scan_detail", kwargs={"scan_id": 0}).replace("/0/", "/"),
        "SHOW_SIDEBAR": request.resolver_match and request.resolver_match.url_name in (
            "dashboard",
            "scan_history",
            "saved_reports",
            "settings",
            "api_settings",
            "profile",
        ),
    }
