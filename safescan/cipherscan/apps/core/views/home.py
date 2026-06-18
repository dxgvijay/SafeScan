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
        context["total_scans"] = ScanHistory.objects.count()
        context["threats_found"] = ScanHistory.objects.exclude(threat_level='safe').count()
        context["files_scanned"] = ScanHistory.objects.filter(scan_type='file').count()
        context["urls_scanned"] = ScanHistory.objects.filter(scan_type='url').count()
        context["scan_change"] = "+12.5"
        context["threat_change"] = "+8.3"
        context["file_change"] = "+5.2"
        context["url_change"] = "+15.7"
        return context


class StatsView(APIView):
    def get(self, request):
        total_scans = ScanHistory.objects.count()
        files_scanned = ScanHistory.objects.filter(scan_type='file').count()
        urls_checked = ScanHistory.objects.filter(scan_type='url').count()
        threats_detected = ScanHistory.objects.exclude(threat_level='safe').count()
        from django.contrib.auth import get_user_model
        User = get_user_model()
        users_protected = User.objects.count()
        return Response({
            'files_scanned': files_scanned,
            'urls_checked': urls_checked,
            'threats_detected': threats_detected,
            'users_protected': users_protected,
        })


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
