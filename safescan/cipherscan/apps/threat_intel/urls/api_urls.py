from django.urls import path

from apps.threat_intel.views.api import threat_intel_view_api

urlpatterns = [
    path("", threat_intel_view_api, name="api_threat_intel"),
]
