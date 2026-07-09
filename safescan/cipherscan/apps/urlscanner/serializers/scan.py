from rest_framework import serializers

from apps.urlscanner.models import URLScan


class URLScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLScan
        fields = [
            "id",
            "url",
            "scanned_at",
            "status",
            "is_malicious",
            "threat_type",
            "threat_score",
            "vendors_total",
            "vendors_flagged",
            "raw_result",
            "scan_duration_ms",
        ]


class URLScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = URLScan
        fields = [
            "id",
            "url",
            "scanned_at",
            "status",
            "is_malicious",
            "threat_type",
            "threat_score",
            "vendors_total",
            "vendors_flagged",
        ]


class URLScanInputSerializer(serializers.Serializer):
    url = serializers.URLField(max_length=2048)
