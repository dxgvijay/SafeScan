from django.views.generic import TemplateView
from apps.accounts.decorators import WorkerRequiredMixin


class WorkerDashboardView(WorkerRequiredMixin, TemplateView):
    template_name = "pages/worker_dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = 'Worker Panel'
        return context
