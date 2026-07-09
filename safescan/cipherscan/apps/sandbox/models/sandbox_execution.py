from django.db import models
from django.conf import settings


class SandboxExecution(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("complete", "Complete"),
        ("error", "Error"),
        ("timeout", "Timeout"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    language = models.CharField(max_length=50)
    code = models.TextField()
    stdin_input = models.TextField(null=True, blank=True)
    output = models.TextField(null=True, blank=True)
    stderr = models.TextField(null=True, blank=True)
    exit_code = models.IntegerField(null=True, blank=True)
    duration_ms = models.FloatField(null=True, blank=True)
    memory_mb = models.FloatField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="pending",
    )
    is_public = models.BooleanField(default=True)
    executed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Sandbox Execution"
        verbose_name_plural = "Sandbox Executions"
        ordering = ["-executed_at"]

    def __str__(self):
        return f"[{self.language}] {self.status} — {self.executed_at}"
