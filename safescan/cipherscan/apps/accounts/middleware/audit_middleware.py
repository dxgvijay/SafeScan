from django.utils import timezone
from apps.accounts.models import LoginAudit, ActivityLog


class LoginAuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        return None


def log_login_attempt(request, user, success, failure_reason=''):
    LoginAudit.objects.create(
        user=user,
        ip_address=request.META.get('REMOTE_ADDR', ''),
        user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        success=success,
        failure_reason=failure_reason,
    )


def log_activity(user, action, details=None, ip_address=None):
    ActivityLog.objects.create(
        user=user,
        action=action,
        details=details or {},
        ip_address=ip_address or '',
    )
