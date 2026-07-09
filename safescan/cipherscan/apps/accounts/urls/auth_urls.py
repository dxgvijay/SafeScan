from django.urls import path, include
from django.views.generic.base import RedirectView
from django.contrib.auth import views as auth_views
from apps.accounts.views import login, logout, registration

urlpatterns = [
    path("login/", login.LoginView.as_view(), name="login"),
    path("logout/", logout.LogoutView.as_view(), name="logout"),
    path("signup/", registration.SignupView.as_view(), name="signup"),
    path(
        "password-reset/",
        auth_views.PasswordResetView.as_view(
            template_name="accounts/password_reset.html",
            email_template_name="accounts/password_reset_email.html",
            subject_template_name="accounts/password_reset_subject.txt",
        ),
        name="password_reset",
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="accounts/password_reset_done.html"
        ),
        name="password_reset_done",
    ),
    path(
        "password-reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="accounts/password_reset_confirm.html"
        ),
        name="password_reset_confirm",
    ),
    path(
        "password-reset/complete/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="accounts/password_reset_complete.html"
        ),
        name="password_reset_complete",
    ),
    path(
        "password-change/",
        auth_views.PasswordChangeView.as_view(
            template_name="accounts/password_change.html",
        ),
        name="password_change",
    ),
    path(
        "password-change/done/",
        auth_views.PasswordChangeDoneView.as_view(
            template_name="accounts/password_change_done.html"
        ),
        name="password_change_done",
    ),
    # Social login shortcuts
    path("google/login/", RedirectView.as_view(url="/accounts/allauth/google/login/?process=login"), name="google_login"),
    path("github/login/", RedirectView.as_view(url="/accounts/allauth/github/login/?process=login"), name="github_login"),
    # django-allauth URLs
    path("allauth/", include("allauth.urls")),
]
