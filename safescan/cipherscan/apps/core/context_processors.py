from django.conf import settings


def site_settings(request):
    return {
        "SITE_NAME": getattr(settings, "SITE_NAME", "CipherScan"),
        "SITE_TAGLINE": "Analyze. Detect. Protect.",
        "CURRENT_YEAR": 2025,
        "SHOW_SIDEBAR": request.resolver_match and request.resolver_match.url_name in (
            "dashboard",
            "scan_history",
            "saved_reports",
            "settings",
            "api_settings",
            "profile",
        ),
    }
