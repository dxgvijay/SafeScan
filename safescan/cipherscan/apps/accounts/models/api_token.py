from django.db import models
from apps.core.models.base import BaseModel

class ApiToken(BaseModel):
    user = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="api_tokens")
    name = models.CharField(max_length=100)
    token = models.CharField(max_length=64, unique=True)
    scopes = models.JSONField(default=list)
    last_used = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
