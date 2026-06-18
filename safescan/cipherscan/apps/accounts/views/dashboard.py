import json
from datetime import datetime, timedelta
from random import randint, choice
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "pages/dashboard.html"

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
        context["api_calls"] = "1.2k"

        scan_types = ["url", "file", "email", "ip"]
        threat_levels = ["safe", "low", "medium", "high", "critical"]
        statuses = ["completed", "processing", "queued", "failed"]

        recent_scans = []
        for i in range(10):
            t = choice(scan_types)
            recent_scans.append({
                "type": t,
                "target": choice([
                    "https://example.com/login",
                    "invoice.pdf",
                    "suspicious-email@phish.com",
                    "192.168.1.105",
                    "https://bank-secure-verify.com",
                    "report.docx",
                    "newsletter@spammer.net",
                    "10.0.0.55",
                    "https://drive-google.com/share",
                    "setup.exe",
                ]),
                "status": choice(statuses),
                "threat_level": choice(threat_levels),
                "date": datetime.now() - timedelta(hours=randint(1, 72), minutes=randint(0, 59)),
                "id": f"{randint(10000, 99999)}",
            })
        context["recent_scans"] = recent_scans

        context["default_scans"] = [
            {"type": "url", "target": "https://example.com", "status": "completed", "threat_level": "safe", "date": datetime.now(), "id": "0"},
        ]

        context["threat_distribution_labels"] = json.dumps(["Malware", "Phishing", "Spam", "Suspicious", "Safe"])
        context["threat_distribution_data"] = json.dumps([35, 28, 18, 12, 7])

        history_data = [randint(30, 85) for _ in range(30)]
        context["scan_history_data"] = json.dumps(history_data)
        context["history_total"] = sum(history_data)

        return context
