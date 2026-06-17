from .base import *

DEBUG = True
SECRET_KEY = "django-insecure-dev-only-key-do-not-use-in-prod"
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS += ["debug_toolbar"]
MIDDLEWARE.insert(0, "debug_toolbar.middleware.DebugToolbarMiddleware")
INTERNAL_IPS = ["127.0.0.1"]

DATABASES["default"]["ENGINE"] = "django.db.backends.sqlite3"
DATABASES["default"]["NAME"] = BASE_DIR / "db.sqlite3"

CELERY_TASK_ALWAYS_EAGER = True
