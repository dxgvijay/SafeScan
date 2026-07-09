from django.urls import path

from apps.filescanner.views.api import file_scan_view

urlpatterns = [
    path("scan/", file_scan_view, name="api_file_scan"),
]
