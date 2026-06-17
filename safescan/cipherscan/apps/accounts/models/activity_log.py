from django.db import models
from apps.core.models.base import BaseModel

class ActivityLog(BaseModel):
    user = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="activities")
    action = models.CharField(max_length=100)
    details = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
