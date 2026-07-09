import os
import logging
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent

dotenv_path = BASE_DIR.parent.parent / ".env"
if dotenv_path.exists():
    load_dotenv(dotenv_path)
    logger.info(f"Loaded .env from {dotenv_path}")
else:
    logger.warning(f"No .env file found at {dotenv_path}")

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "django-insecure-change-me")
DEBUG = False
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "corsheaders",
    "django_filters",
    "django_celery_beat",
    "django_celery_results",
    "apps.core",
    "apps.accounts",
    "apps.phishing",
    "apps.urlscanner",
    "apps.filescanner",
    "apps.sandbox",
    "apps.browser_isolation",
    "apps.threat_intel",
    "apps.darkweb",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.core.middleware.security_headers.SecurityHeadersMiddleware",
    "apps.core.middleware.rate_limit.RateLimitMiddleware",
    "apps.core.middleware.request_logging.RequestLoggingMiddleware",
    "apps.core.middleware.ip_blocklist.IPBlocklistMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.CustomUser"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "home"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    {"NAME": "apps.accounts.validators.CustomPasswordValidator"},
]

# django-allauth
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]
INSTALLED_APPS += [
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "allauth.socialaccount.providers.github",
]
SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "APP": {
            "client_id": os.environ.get("GOOGLE_CLIENT_ID", ""),
            "secret": os.environ.get("GOOGLE_CLIENT_SECRET", ""),
            "key": "",
        },
        "SCOPE": ["profile", "email"],
        "AUTH_PARAMS": {"access_type": "online"},
    },
    "github": {
        "APP": {
            "client_id": os.environ.get("GITHUB_CLIENT_ID", ""),
            "secret": os.environ.get("GITHUB_CLIENT_SECRET", ""),
            "key": "",
        },
        "SCOPE": ["user:email"],
    },
}
SOCIALACCOUNT_ONLY = False
SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
SOCIALACCOUNT_EMAIL_VERIFICATION = "none"
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_LOGIN_ON_GET = True
SOCIALACCOUNT_ADAPTER = "apps.accounts.utils.social_adapters.CustomSocialAccountAdapter"
ACCOUNT_LOGIN_METHODS = {"username", "email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "username*", "password1*", "password2*"]
ACCOUNT_EMAIL_VERIFICATION = "none"
ACCOUNT_LOGIN_ON_PASSWORD_RESET = True

# Login rate limiting — using django-axes
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = 0.5  # 30 minutes
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]

INSTALLED_APPS += [
    "axes",
]

MIDDLEWARE += [
    "allauth.account.middleware.AccountMiddleware",
    "axes.middleware.AxesMiddleware",
    "apps.accounts.middleware.audit_middleware.LoginAuditMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.core.context_processors.site_settings",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "cipherscan"),
        "USER": os.environ.get("DB_USER", "cipherscan"),
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
    }
}

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY in ("your_api_key_here", "YOUR_VIRUSTOTAL_API_KEY"):
    logger.warning(
        "VIRUSTOTAL_API_KEY is empty or still set to the default placeholder. "
        "URL scanning will fail. Set a real API key in the .env file."
    )

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY in ("your_api_key_here", "YOUR_ABUSEIPDB_API_KEY"):
    logger.warning(
        "ABUSEIPDB_API_KEY is empty or still set to the default placeholder. "
        "IP abuse checks will fail. Set a real API key in the .env file."
    )

MALWAREBAZAAR_API_KEY = os.environ.get("MALWAREBAZAAR_API_KEY", "")
if not MALWAREBAZAAR_API_KEY or MALWAREBAZAAR_API_KEY in ("your_api_key_here", "YOUR_MALWAREBAZAAR_API_KEY"):
    logger.warning(
        "MALWAREBAZAAR_API_KEY is empty or still set to the default placeholder. "
        "MalwareBazaar lookups will fail. Set a real API key in the .env file."
    )

HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
if not HIBP_API_KEY or HIBP_API_KEY in ("your_api_key_here", "YOUR_HIBP_API_KEY"):
    logger.warning(
        "HIBP_API_KEY is not configured. Breach data will be unavailable. "
        "Set a real HaveIBeenPwned API key in the .env file."
    )

CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = "django-db"
