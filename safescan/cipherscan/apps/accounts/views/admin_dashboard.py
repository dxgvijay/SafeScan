from django.contrib.auth import get_user_model
from django.views.generic import TemplateView
from apps.accounts.decorators import AdminRequiredMixin

User = get_user_model()


class AdminDashboardView(AdminRequiredMixin, TemplateView):
    template_name = "pages/admin_dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context["total_users"] = User.objects.count()
        context["admins"] = User.objects.filter(is_superuser=True).count()
        context["staff"] = User.objects.filter(is_staff=True).count()
        context["workers"] = User.objects.filter(groups__name="Worker").count()

        try:
            from apps.accounts.models import LoginAudit
            context["failed_logins"] = LoginAudit.objects.filter(success=False).count()
        except Exception:
            context["failed_logins"] = "No data available"

        try:
            from apps.accounts.models import ActivityLog
            context["recent_activity"] = ActivityLog.objects.select_related(
                "user"
            ).order_by("-created_at")[:20]
        except Exception:
            context["recent_activity"] = []

        try:
            from apps.accounts.accounts.models import ScanHistory
            context["scan_count"] = ScanHistory.objects.count()
        except Exception:
            context["scan_count"] = "No data available"

        context["page_title"] = "Admin Panel"
        return context
