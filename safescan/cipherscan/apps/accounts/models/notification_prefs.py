from django.db import models
from apps.core.models.base import BaseModel

class NotificationPrefs(BaseModel):
    user = models.OneToOneField("accounts.User", on_delete=models.CASCADE, related_name="notification_prefs")
    email_alerts = models.BooleanField(default=True)
    scan_completed = models.BooleanField(default=True)
    threat_detected = models.BooleanField(default=True)
    weekly_report = models.BooleanField(default=False)
    marketing = models.BooleanField(default=False)
