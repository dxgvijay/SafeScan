from django.urls import path
from apps.phishing.phishing.api_views import (
    PhishingStatsView,
    domain_health_view,
    email_content_scan_view,
    email_header_analyze_view,
)

urlpatterns = [
    path("stats", PhishingStatsView.as_view(), name="phishing_stats_api"),
    path("analyze-header/", email_header_analyze_view, name="api_email_header_analyze"),
    path("domain-health/", domain_health_view, name="api_domain_health"),
    path("scan-email/", email_content_scan_view, name="api_email_content_scan"),
]