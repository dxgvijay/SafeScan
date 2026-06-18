from django.conf import settings
from django.db import models
from apps.core.models.base import BaseModel

class TwoFactorAuth(BaseModel):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="two_factor")
    totp_secret = models.CharField(max_length=64)
    backup_codes = models.JSONField(default=list)
    is_active = models.BooleanField(default=False)
    last_verified = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
