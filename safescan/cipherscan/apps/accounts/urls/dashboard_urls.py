from django.urls import path
from apps.accounts.views.dashboard import DashboardView

urlpatterns = [
    path("", DashboardView.as_view(), name="dashboard"),
]
