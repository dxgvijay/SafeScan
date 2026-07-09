import json
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.core.exceptions import ObjectDoesNotExist

from apps.accounts.models.profile import Profile
from apps.accounts.services import DashboardStatsService


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "pages/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        svc = DashboardStatsService(user=self.request.user)

        try:
            self.request.user.profile
        except ObjectDoesNotExist:
            Profile.objects.create(user=self.request.user)

        context["total_scans"] = svc.get_total_scans()
        context["threats_found"] = svc.get_total_threats()
        context["files_scanned"] = svc.get_files_scanned()
        context["urls_scanned"] = svc.get_urls_scanned()

        context["scan_change"] = svc.get_scan_change_pct()
        context["threat_change"] = svc.get_scan_change_pct()
        context["file_change"] = svc.get_scan_change_pct(scan_type='file')
        context["url_change"] = svc.get_scan_change_pct(scan_type='url')

        context["recent_scans"] = svc.get_recent_activity(limit=20)

        distribution = svc.get_threat_distribution()
        context["threat_distribution_labels"] = json.dumps(distribution['labels'])
        context["threat_distribution_data"] = json.dumps(distribution['data'])

        history = svc.get_scan_history(days=30)
        context["scan_history_data"] = json.dumps(history['data'])
        context["history_total"] = history['total']

        user_stats = svc.get_user_statistics()
        context["api_calls"] = user_stats.get('api_calls', 0)
        context["user_scans"] = user_stats.get('user_scans', 0)
        context["reports_exported"] = user_stats.get('reports_exported', 0)

        context["quick_scans"] = svc.get_quick_scans(limit=10)
        context["notifications_count"] = svc.get_notification_count()

        context["default_scans"] = []

        return context
