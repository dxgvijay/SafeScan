from django.urls import path
from apps.accounts.views.profile import ProfileView

urlpatterns = [
    path("", ProfileView.as_view(), name="profile"),
]
