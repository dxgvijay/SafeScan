from django.db import models


class ScanResult(models.Model):
    query = models.CharField(max_length=255, db_index=True)
    asset_type = models.CharField(max_length=50)
    risk_score = models.IntegerField()
    breach_count = models.IntegerField(default=0)
    total_records_exposed = models.BigIntegerField(default=0)
    scanned_at = models.DateTimeField(auto_now_add=True, db_index=True)
    response_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-scanned_at"]
        verbose_name = "scan result"
        verbose_name_plural = "scan results"

    def __str__(self):
        return f"{self.query} ({self.asset_type}) — risk {self.risk_score}"
