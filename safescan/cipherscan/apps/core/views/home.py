import json
from datetime import datetime, timedelta
from random import randint, choice
from django.views.generic import TemplateView


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
