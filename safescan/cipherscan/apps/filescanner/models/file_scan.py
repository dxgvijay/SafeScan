from django.conf import settings
from django.db import models


class FileScan(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("uploading", "Uploading"),
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
    file_name = models.CharField(max_length=255)
    file_size = models.IntegerField()
    file_type = models.CharField(max_length=100, null=True, blank=True)
    file_hash_md5 = models.CharField(max_length=32, null=True, blank=True)
    file_hash_sha256 = models.CharField(max_length=64, null=True, blank=True)
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
        verbose_name = "File Scan"
        verbose_name_plural = "File Scans"
        ordering = ["-scanned_at"]

    def __str__(self):
        return f"{self.file_name} ({self.status})"
