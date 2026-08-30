"""
Settings for the reproducible benchmark/attack-test companion project to
'Web Security Enhancement in Django'.

Run the same server four times, once per SECURITY_LEVEL, to reproduce the
four rows of the paper's Table 3 (Performance Overhead) with REAL numbers
instead of illustrative estimates:

    SECURITY_LEVEL=baseline      python manage.py runserver 8001
    SECURITY_LEVEL=headers       python manage.py runserver 8001
    SECURITY_LEVEL=sanitization  python manage.py runserver 8001
    SECURITY_LEVEL=full          python manage.py runserver 8001

(stop the server and change SECURITY_LEVEL between runs; each run is a
separate, independently benchmarked configuration, exactly like Table 3's
four rows).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Which configuration layer is active for this run --------------------
# baseline | headers | sanitization | full
SECURITY_LEVEL = os.environ.get("SECURITY_LEVEL", "baseline")

SECRET_KEY = "test-kit-only-not-for-production-" + "x" * 32
DEBUG = True
ALLOWED_HOSTS = ["*"]

# A throwaway Fernet key generated once per test run is fine for a local
# benchmark; for anything beyond local testing, load this from the
# environment instead (as the paper's settings.py excerpt does).
os.environ.setdefault(
    "FIELD_ENCRYPTION_KEY", "wq9k3q1nB6b8m4o9s2u5x8z1B4E7H0K3M6P9S2U5X8Z="
)

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "secapp",
]
if SECURITY_LEVEL in ("headers", "sanitization", "full"):
    INSTALLED_APPS.append("csp")

_base_middleware = [
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]
if SECURITY_LEVEL in ("headers", "sanitization", "full"):
    _base_middleware += [
        "django.middleware.security.SecurityMiddleware",
        "django.middleware.clickjacking.XFrameOptionsMiddleware",
        "csp.middleware.CSPMiddleware",
    ]
MIDDLEWARE = _base_middleware

ROOT_URLCONF = "testproject.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "testproject.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Security settings, gated by SECURITY_LEVEL (mirrors paper Table 1) --
if SECURITY_LEVEL in ("headers", "sanitization", "full"):
    X_FRAME_OPTIONS = "DENY"
    SESSION_COOKIE_SECURE = False  # True in production (HTTPS); False so
    CSRF_COOKIE_SECURE = False     # the local http:// benchmark server works
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    CSRF_COOKIE_SAMESITE = "Strict"
    SECURE_CONTENT_TYPE_NOSNIFF = True

    CONTENT_SECURITY_POLICY = {
        "DIRECTIVES": {
            "default-src": ("'self'",),
            "script-src": ("'self'",),
            "style-src": ("'self'",),
            "frame-ancestors": ("'none'",),
        }
    }
else:
    X_FRAME_OPTIONS = "SAMEORIGIN"  # Django's own default, i.e. "no extra hardening applied"

# Feature flags read by secapp/views.py and secapp/models.py
SANITIZE_INPUT = SECURITY_LEVEL in ("sanitization", "full")
ENCRYPT_SENSITIVE_FIELDS = SECURITY_LEVEL == "full"
