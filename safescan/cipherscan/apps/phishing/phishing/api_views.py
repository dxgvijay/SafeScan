from rest_framework.views import APIView
from rest_framework.response import Response


class PhishingStatsView(APIView):
    def get(self, request):
        from apps.phishing.phishing.models import EmailHeaderScan, EmailHealthCheck, SuspiciousEmailReport
        return Response({
            'headers_analyzed': EmailHeaderScan.objects.count(),
            'emails_blocked': SuspiciousEmailReport.objects.filter(
                verdict__in=['suspicious', 'phishing']
            ).count(),
            'domains_checked': EmailHealthCheck.objects.count(),
        })
