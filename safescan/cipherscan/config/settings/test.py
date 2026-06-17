from .base import *

DEBUG = False
SECRET_KEY = "test-secret-key"
DATABASES["default"]["ENGINE"] = "django.db.backends.sqlite3"
DATABASES["default"]["NAME"] = ":memory:"
CELERY_TASK_ALWAYS_EAGER = True
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
