from django.urls import path
from apps.core.views.api import StatsView

urlpatterns = [
    path("stats/", StatsView.as_view(), name="api_stats"),
]
