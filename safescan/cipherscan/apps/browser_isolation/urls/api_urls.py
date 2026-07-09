from django.urls import path
from apps.browser_isolation.views.api import browser_isolation_view_api

urlpatterns = [
    path("scan/", browser_isolation_view_api, name="api_browser_isolation_scan"),
]
