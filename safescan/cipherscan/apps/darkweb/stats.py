from django.conf import settings
from django.core.cache import cache
from django.db.models import Sum, Avg

from .models import ScanResult

CACHE_KEY = "darkweb_dashboard_stats"
CACHE_TTL = 60


def get_total_assets() -> int:
    return _get_stats()["total_assets"]


def get_total_breaches() -> int:
    return _get_stats()["total_breaches"]


def get_average_risk() -> int:
    return _get_stats()["average_risk"]


def get_dashboard_stats() -> dict:
    return _get_stats()


def _get_stats() -> dict:
    stats = cache.get(CACHE_KEY)
    if stats is not None:
        return stats

    total_assets = ScanResult.objects.count()
    total_breaches = ScanResult.objects.aggregate(total=Sum("breach_count"))["total"] or 0
    avg_risk = ScanResult.objects.aggregate(avg=Avg("risk_score"))["avg"] or 0
    hibp_key = getattr(settings, "HIBP_API_KEY", "")
    monitoring_online = bool(hibp_key)

    stats = {
        "total_assets": total_assets,
        "total_breaches": total_breaches,
        "average_risk": round(avg_risk),
        "monitoring_online": monitoring_online,
    }

    cache.set(CACHE_KEY, stats, CACHE_TTL)
    return stats
