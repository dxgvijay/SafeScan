from django.urls import path

from apps.darkweb.views import analyze_view, index, stats_view

app_name = "darkweb"

urlpatterns = [
    path("", index, name="index"),
    path("analyze/", analyze_view, name="analyze"),
    path("stats/", stats_view, name="stats"),
]
