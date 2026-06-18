import json
from datetime import timedelta
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from django.views.generic import TemplateView
from apps.accounts.accounts.models import ScanHistory
from apps.core.context_processors import global_stats


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "pages/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        stats = global_stats(self.request)
        context.update(stats)

        now = timezone.now()
        last_30 = now - timedelta(days=30)
        last_60 = now - timedelta(days=60)

        # Recent scans for the current user
        recent_scans = ScanHistory.objects.filter(user=self.request.user)[:10]
        context["recent_scans"] = [
            {
                "type": s.scan_type,
                "target": s.target,
                "status": "completed",
                "threat_level": s.threat_level,
                "date": s.created_at,
                "id": str(s.id),
            }
            for s in recent_scans
        ]
        if not context["recent_scans"]:
            context["recent_scans"] = [
                {
                    "type": "url",
                    "target": "",
                    "status": "completed",
                    "threat_level": "safe",
                    "date": now,
                    "id": "0",
                },
            ]

        context["api_calls"] = "0"

        # Threat distribution from DB
        threat_qs = (
            ScanHistory.objects.values("threat_level")
            .annotate(count=Count("id"))
            .order_by("-count")
        )
        threat_labels = []
        threat_data = []
        for entry in threat_qs:
            label = entry["threat_level"].title() if entry["threat_level"] else "Unknown"
            threat_labels.append(label)
            threat_data.append(entry["count"])

        if not threat_labels:
            threat_labels = ["Safe"]
            threat_data = [0]

        context["threat_distribution_labels"] = json.dumps(threat_labels)
        context["threat_distribution_data"] = json.dumps(threat_data)

        # Scan history - last 30 days
        history_qs = (
            ScanHistory.objects.filter(created_at__gte=last_30)
            .annotate(date=TruncDate("created_at"))
            .values("date")
            .annotate(count=Count("id"))
            .order_by("date")
        )

        history_map = {entry["date"]: entry["count"] for entry in history_qs}
        history_data = []
        for i in range(29, -1, -1):
            day = (now - timedelta(days=i)).date()
            history_data.append(history_map.get(day, 0))

        context["scan_history_data"] = json.dumps(history_data)
        context["history_total"] = sum(history_data)

        return context
