from django.conf import settings
from django.db import models
from apps.core.models.base import BaseModel

class Profile(BaseModel):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)
    display_name = models.CharField(max_length=100, blank=True)
    company = models.CharField(max_length=200, blank=True)
    job_title = models.CharField(max_length=200, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    timezone = models.CharField(max_length=50, default="UTC")
    email_notifications = models.BooleanField(default=True)
    scan_notifications = models.BooleanField(default=True)
    threat_alerts = models.BooleanField(default=True)
    weekly_digest = models.BooleanField(default=False)
