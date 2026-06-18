from datetime import timedelta

from django.conf import settings
from django.utils import timezone


def site_settings(request):
    return {
        "SITE_NAME": getattr(settings, "SITE_NAME", "CipherScan"),
        "SITE_TAGLINE": "Analyze. Detect. Protect.",
        "CURRENT_YEAR": timezone.now().year,
        "SHOW_SIDEBAR": request.resolver_match and request.resolver_match.url_name in (
            "dashboard",
            "scan_history",
            "saved_reports",
            "settings",
            "api_settings",
            "profile",
        ),
    }


def global_stats(request):
    from django.contrib.auth import get_user_model
    from apps.accounts.accounts.models import ScanHistory

    total_scans = ScanHistory.objects.count()
    threats_found = ScanHistory.objects.exclude(threat_level="safe").count()
    files_scanned = ScanHistory.objects.filter(scan_type="file").count()
    urls_scanned = ScanHistory.objects.filter(scan_type="url").count()

    now = timezone.now()
    last_30 = now - timedelta(days=30)
    prev_30 = now - timedelta(days=60)

    def pct_change(current, previous):
        if previous == 0:
            return "+0"
        chg = round(((current - previous) / previous) * 100, 1)
        return f"+{chg}" if chg >= 0 else str(chg)

    urls_last_30 = ScanHistory.objects.filter(
        created_at__gte=last_30, scan_type="url"
    ).count()

    recent_total = ScanHistory.objects.filter(created_at__gte=last_30).count()
    prev_total = ScanHistory.objects.filter(
        created_at__gte=prev_30, created_at__lt=last_30
    ).count()

    recent_threats = (
        ScanHistory.objects.filter(created_at__gte=last_30)
        .exclude(threat_level="safe")
        .count()
    )
    prev_threats = (
        ScanHistory.objects.filter(created_at__gte=prev_30, created_at__lt=last_30)
        .exclude(threat_level="safe")
        .count()
    )

    recent_files = ScanHistory.objects.filter(
        created_at__gte=last_30, scan_type="file"
    ).count()
    prev_files = ScanHistory.objects.filter(
        created_at__gte=prev_30, created_at__lt=last_30, scan_type="file"
    ).count()

    recent_urls = ScanHistory.objects.filter(
        created_at__gte=last_30, scan_type="url"
    ).count()
    prev_urls = ScanHistory.objects.filter(
        created_at__gte=prev_30, created_at__lt=last_30, scan_type="url"
    ).count()

    User = get_user_model()
    users_count = User.objects.count()
    vendors_count = 0

    detection_rate = 0.0
    if total_scans > 0:
        detection_rate = round((threats_found / total_scans) * 100, 2)

    return {
        "total_scans": total_scans,
        "threats_found": threats_found,
        "files_scanned": files_scanned,
        "urls_scanned": urls_scanned,
        "users_count": users_count,
        "vendors_count": vendors_count,
        "urls_last_30_days": urls_last_30,
        "detection_rate": detection_rate,
        "scan_change": pct_change(recent_total, prev_total),
        "threat_change": pct_change(recent_threats, prev_threats),
        "file_change": pct_change(recent_files, prev_files),
        "url_change": pct_change(recent_urls, prev_urls),
    }
