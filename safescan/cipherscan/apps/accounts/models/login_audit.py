from django.db import models
from apps.core.models.base import BaseModel

class LoginAudit(BaseModel):
    user = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="login_audits")
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    location = models.CharField(max_length=255, blank=True)
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=100, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
