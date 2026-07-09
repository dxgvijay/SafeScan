from django.conf import settings
from django.db import models


class URLScan(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("scanning", "Scanning"),
        ("complete", "Complete"),
        ("error", "Error"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    url = models.URLField(max_length=2048)
    scanned_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    is_malicious = models.BooleanField(null=True, blank=True)
    threat_type = models.CharField(max_length=100, null=True, blank=True)
    threat_score = models.IntegerField(null=True, blank=True)
    vendors_total = models.IntegerField(default=0)
    vendors_flagged = models.IntegerField(default=0)
    raw_result = models.JSONField(null=True, blank=True)
    scan_duration_ms = models.IntegerField(null=True, blank=True)

    class Meta:
        verbose_name = "URL Scan"
        verbose_name_plural = "URL Scans"
        ordering = ["-scanned_at"]

    def __str__(self):
        return f"{self.url} ({self.status})"
