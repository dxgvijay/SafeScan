from django.db import models
from django.conf import settings


class IsolationScan(models.Model):
    RISK_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    url = models.URLField(max_length=2048)
    status = models.CharField(max_length=20, default="pending")
    error_message = models.TextField(null=True, blank=True)

    page_title = models.CharField(max_length=500, null=True, blank=True)
    final_url = models.URLField(max_length=2048, null=True, blank=True)
    http_status = models.IntegerField(null=True, blank=True)
    server_header = models.CharField(max_length=200, null=True, blank=True)
    content_type = models.CharField(max_length=200, null=True, blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    redirect_count = models.IntegerField(default=0)
    load_time_ms = models.FloatField(null=True, blank=True)

    dom_nodes = models.IntegerField(default=0)
    images = models.IntegerField(default=0)
    links = models.IntegerField(default=0)
    css_files = models.IntegerField(default=0)
    scripts_removed = models.IntegerField(default=0)
    inline_scripts_removed = models.IntegerField(default=0)
    external_scripts_removed = models.IntegerField(default=0)
    forms_removed = models.IntegerField(default=0)
    iframes_removed = models.IntegerField(default=0)
    objects_removed = models.IntegerField(default=0)
    event_handlers_removed = models.IntegerField(default=0)
    dangerous_urls_removed = models.IntegerField(default=0)
    meta_refresh_removed = models.IntegerField(default=0)
    mixed_content_found = models.IntegerField(default=0)

    risk_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=20, choices=RISK_CHOICES, default="low")

    sanitized_html = models.TextField(null=True, blank=True)
    raw_html = models.TextField(null=True, blank=True)
    response_headers = models.JSONField(null=True, blank=True)
    redirect_chain = models.JSONField(null=True, blank=True, default=list)
    removed_elements = models.JSONField(null=True, blank=True, default=list)
    security_headers = models.JSONField(null=True, blank=True, default=dict)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Isolation Scan"
        verbose_name_plural = "Isolation Scans"
        ordering = ["-created_at"]

    def __str__(self):
        return f"[{self.get_risk_level_display()}] {self.url} — {self.created_at}"
