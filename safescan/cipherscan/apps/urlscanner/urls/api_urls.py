from django.urls import path

from apps.urlscanner.views.api import (
    recent_scans_view,
    url_scan_result_view,
    url_scan_view,
)

urlpatterns = [
    path("scan/url/", url_scan_view, name="api_url_scan"),
    path("scan/url/<int:scan_id>/", url_scan_result_view, name="api_url_scan_result"),
    path("recent/", recent_scans_view, name="recent_scans"),
]
