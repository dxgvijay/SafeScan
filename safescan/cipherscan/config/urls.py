from django.conf import settings
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("apps.core.urls.core_urls")),
    path("accounts/", include("apps.accounts.urls.auth_urls")),
    path("profile/", include("apps.accounts.urls.profile_urls")),
    path("dashboard/", include("apps.accounts.urls.dashboard_urls")),
    path("api/accounts/", include("apps.accounts.urls.api_urls")),
    path("phishing/", include("apps.phishing.urls.analysis_urls")),
    path("phishing/health/", include("apps.phishing.urls.health_urls")),
    path("phishing/blocker/", include("apps.phishing.urls.blocker_urls")),
    path("api/phishing/", include("apps.phishing.urls.api_urls")),
    path("url-scanner/", include("apps.urlscanner.urls.scan_urls")),
    path("url-scanner/reports/", include("apps.urlscanner.urls.report_urls")),
    path("url-scanner/community/", include("apps.urlscanner.urls.community_urls")),
    path("api/url-scanner/", include("apps.urlscanner.urls.api_urls")),
    path("file-scanner/", include("apps.filescanner.urls.upload_urls")),
    path("file-scanner/scan/", include("apps.filescanner.urls.scan_urls")),
    path("file-scanner/reports/", include("apps.filescanner.urls.report_urls")),
    path("file-scanner/yara/", include("apps.filescanner.urls.yara_urls")),
    path("api/file-scanner/", include("apps.filescanner.urls.api_urls")),
    path("sandbox/", include("apps.sandbox.urls.sandbox_urls")),
    path("sandbox/snippets/", include("apps.sandbox.urls.snippet_urls")),
    path("api/sandbox/", include("apps.sandbox.urls.api_urls")),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
