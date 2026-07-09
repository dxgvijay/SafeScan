from apps.accounts.views.login import LoginView
from apps.accounts.views.logout import LogoutView
from apps.accounts.views.registration import SignupView
from apps.accounts.views.dashboard import DashboardView
from apps.accounts.views.profile import ProfileView
from apps.accounts.views.admin_dashboard import AdminDashboardView
from apps.accounts.views.worker_dashboard import WorkerDashboardView

__all__ = [
    'LoginView',
    'LogoutView',
    'SignupView',
    'DashboardView',
    'ProfileView',
    'AdminDashboardView',
    'WorkerDashboardView',
]
