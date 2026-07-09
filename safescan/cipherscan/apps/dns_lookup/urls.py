from django.urls import path

from apps.dns_lookup.views import dns_lookup_view_api

urlpatterns = [
    path("", dns_lookup_view_api, name="api_dns_lookup"),
]
