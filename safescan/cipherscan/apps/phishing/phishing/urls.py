from django.urls import path
from . import views

app_name = 'phishing'

urlpatterns = [
    path('header-analyzer/', views.header_analyzer_view, name='header_analyzer'),
    path('email-health/', views.email_health_view, name='email_health'),
    path('suspicious-email/', views.suspicious_email_view, name='suspicious_email'),
]
