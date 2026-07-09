from django.urls import path

from apps.ip_scanner.views import ip_scan_view_api

urlpatterns = [
    path("", ip_scan_view_api, name="api_ip_scan"),
]
