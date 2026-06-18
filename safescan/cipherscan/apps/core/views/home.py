from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Count
from django.db.models.functions import TruncMonth
from django.utils import timezone
from django.views.generic import TemplateView
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.accounts.accounts.models import ScanHistory
from apps.core.context_processors import global_stats


class HomeView(TemplateView):
    template_name = "pages/home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        stats = global_stats(self.request)
        context.update(stats)
        return context


class StatsView(APIView):
    def get(self, request):
        total_scans = ScanHistory.objects.count()
        files_scanned = ScanHistory.objects.filter(scan_type='file').count()
        urls_scanned = ScanHistory.objects.filter(scan_type='url').count()
        threats_detected = ScanHistory.objects.exclude(threat_level='safe').count()
        User = get_user_model()
        users_protected = User.objects.count()

        now = timezone.now()
        last_30 = now - timedelta(days=30)
        urls_last_30 = ScanHistory.objects.filter(
            created_at__gte=last_30, scan_type='url'
        ).count()

        detection_rate = 0.0
        if total_scans > 0:
            detection_rate = round((threats_detected / total_scans) * 100, 2)

        return Response({
            'total_scans': total_scans,
            'files_scanned': files_scanned,
            'urls_scanned': urls_scanned,
            'threats_detected': threats_detected,
            'users_protected': users_protected,
            'vendors_count': 0,
            'urls_last_30_days': urls_last_30,
            'detection_rate': detection_rate,
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
