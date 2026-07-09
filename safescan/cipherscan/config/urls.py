from django.conf import settings
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

from apps.accounts.views.admin_dashboard import AdminDashboardView
from apps.accounts.views.worker_dashboard import WorkerDashboardView
from apps.browser_isolation.views.api import browser_isolation_view_api
from apps.filescanner.views.api import (
    file_recent_view,
    file_scan_view,
    file_search_view,
)
from apps.sandbox.views.api import (
    sandbox_execute_view,
    sandbox_recent_view,
    sandbox_stats_view,
)
from apps.darkweb.views import scan_view
from apps.sandbox.views.tools_api import (
    port_scan_view,
    hash_calc_view,
)
from apps.accounts.views.api import user_scan_history_api
from apps.urlscanner.views.api import (
    stats_view,
    url_scan_result_view,
    url_scan_view,
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("apps.core.urls.core_urls")),
    path("api/browser-isolation/", browser_isolation_view_api, name="api_browser_isolation"),
    path("accounts/", include("apps.accounts.urls.auth_urls")),
    path("profile/", include("apps.accounts.urls.profile_urls")),
    path("dashboard/", include("apps.accounts.urls.dashboard_urls")),
    path("admin-panel/", AdminDashboardView.as_view(), name="admin_panel"),
    path("worker/", WorkerDashboardView.as_view(), name="worker_dashboard"),
    path("api/accounts/", include("apps.accounts.urls.api_urls")),
    path("phishing/", include("apps.phishing.urls.analysis_urls")),
    path("phishing/health/", include("apps.phishing.urls.health_urls")),
    path("phishing/blocker/", include("apps.phishing.urls.blocker_urls")),
    path("api/phishing/", include("apps.phishing.urls.api_urls")),
    path("url-scanner/", RedirectView.as_view(url="/browser-isolation/", permanent=True)),
    path("url-scanner/reports/", RedirectView.as_view(url="/browser-isolation/", permanent=True)),
    path("url-scanner/community/", RedirectView.as_view(url="/browser-isolation/", permanent=True)),
    path("api/url-scanner/", include("apps.urlscanner.urls.api_urls")),
    path("file-scanner/", include("apps.filescanner.urls.upload_urls")),
    path("file-scanner/scan/", include("apps.filescanner.urls.scan_urls")),
    path("file-scanner/reports/", include("apps.filescanner.urls.report_urls")),
    path("file-scanner/yara/", include("apps.filescanner.urls.yara_urls")),
    path("api/file/scan/", file_scan_view, name="api_file_scan"),
    path("api/file/recent/", file_recent_view, name="api_file_recent"),
    path("api/file/search/", file_search_view, name="api_file_search"),
    path("api/file-scanner/", include("apps.filescanner.urls.api_urls")),
    path("sandbox/", include("apps.sandbox.urls.sandbox_urls")),
    path("sandbox/snippets/", include("apps.sandbox.urls.snippet_urls")),
    path('api/sandbox/execute/', sandbox_execute_view, name='api_sandbox_execute'),
    path('api/sandbox/recent/', sandbox_recent_view, name='api_sandbox_recent'),
    path('api/sandbox/stats/', sandbox_stats_view, name='api_sandbox_stats'),
    path('api/sandbox/port-scan/', port_scan_view, name='api_sandbox_port_scan'),
    path('api/sandbox/hash-calc/', hash_calc_view, name='api_sandbox_hash_calc'),
    path("api/user/scan-history/", user_scan_history_api, name="scan_history_api"),
    path("api/stats/", stats_view, name="api_stats"),
    path("api/scan/url/", url_scan_view, name="api_url_scan"),
    path("api/scan/url/<int:scan_id>/", url_scan_result_view, name="api_url_scan_result"),
    path("api/threat-intel/", include("apps.threat_intel.urls.api_urls")),
    path("api/darkweb/scan/", scan_view, name="api_darkweb_scan"),
    path("darkweb/", include("apps.darkweb.urls")),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
