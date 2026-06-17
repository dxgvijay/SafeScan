from .base import *

DEBUG = False
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ALLOWED_HOSTS = os.environ["DJANGO_ALLOWED_HOSTS"].split(",")

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"

STATIC_ROOT = "/var/www/cipherscan/staticfiles"
MEDIA_ROOT = "/var/www/cipherscan/media"

LOGGING = {
    "version": 1,
    "handlers": {"file": {"level": "ERROR", "class": "logging.FileHandler", "filename": BASE_DIR / "logs" / "django.log"}},
    "root": {"handlers": ["file"], "level": "ERROR"},
}
