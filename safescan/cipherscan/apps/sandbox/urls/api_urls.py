from django.urls import path

from apps.sandbox.views.api import sandbox_execute_view, sandbox_recent_view

urlpatterns = [
    path("execute/", sandbox_execute_view, name="api_sandbox_execute"),
    path("recent/", sandbox_recent_view, name="api_sandbox_recent"),
]