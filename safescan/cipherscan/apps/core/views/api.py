from rest_framework.views import APIView
from rest_framework.response import Response
from apps.accounts.accounts.models import ScanHistory, CustomUser


class StatsView(APIView):
    def get(self, request):
        files_scanned = ScanHistory.objects.filter(scan_type="file").count()
        urls_checked = ScanHistory.objects.filter(scan_type="url").count()
        threats_detected = ScanHistory.objects.filter(
            threat_level__in=["suspicious", "malicious"]
        ).count()
        users_protected = CustomUser.objects.count()

        return Response({
            "files_scanned": files_scanned,
            "urls_checked": urls_checked,
            "threats_detected": threats_detected,
            "users_protected": users_protected,
        })
