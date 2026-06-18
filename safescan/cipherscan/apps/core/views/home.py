import json
from datetime import datetime, timedelta
from random import randint, choice
from django.db.models import Count
from django.db.models.functions import TruncMonth
from django.utils import timezone
from django.views.generic import TemplateView
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.accounts.accounts.models import ScanHistory


class HomeView(TemplateView):
    template_name = "pages/home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["total_scans"] = 18473
        context["threats_found"] = 521
        context["files_scanned"] = 8473
        context["urls_scanned"] = 12984
        context["scan_change"] = "+12.5"
        context["threat_change"] = "+8.3"
        context["file_change"] = "+5.2"
        context["url_change"] = "+15.7"
        return context


class ThreatHistoryView(APIView):
    def get(self, request):
        six_months_ago = timezone.now() - timedelta(days=180)
        queryset = (
            ScanHistory.objects
            .filter(created_at__gte=six_months_ago)
            .exclude(threat_level='safe')
            .annotate(month=TruncMonth('created_at'))
            .values('month')
            .annotate(count=Count('id'))
            .order_by('month')
        )

        labels = []
        data = []
        for entry in queryset:
            labels.append(entry['month'].strftime('%b') if entry['month'] else '')
            data.append(entry['count'])

        change_percent = 0
        if len(data) >= 2:
            prev = data[-2]
            curr = data[-1]
            if prev > 0:
                change_percent = round(((curr - prev) / prev) * 100, 1)

        return Response({
            'labels': labels,
            'data': data,
            'change_percent': change_percent,
        })
