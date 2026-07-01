from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
<<<<<<< HEAD
    path('', include('cipherscan.config.urls')),
=======
    path('', include('cipherscan.urls')),
>>>>>>> b6062812c96d3b9950c91754df7bfb627ec5b377
]