import two_factor.urls
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('allauth.urls')),
    path('', include(two_factor.urls.urlpatterns)),
    path('dashboard/', include('dashboard.urls')),
    path('phishing/', include('phishing.urls')),
    path('urlscanner/', include('urlscanner.urls')),
    path('filescanner/', include('filescanner.urls')),
    path('codesandbox/', include('codesandbox.urls')),
    path('account/', include('accounts.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
