from django.urls import path
from apps.phishing.phishing.api_views import PhishingStatsView

urlpatterns = [
    path("stats", PhishingStatsView.as_view(), name="phishing_stats_api"),
]