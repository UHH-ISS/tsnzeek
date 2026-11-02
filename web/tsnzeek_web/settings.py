# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
"""Settings of the TSNZeek web interface. No database: it reads the files of the IDS and Zeek and writes control.json.

Environment (all optional):
  TSNZEEK_DIR          base directory of a headless run (default ~/tsnzeek): logs/ and control/ below it
  TSNZEEK_CONTROL_DIR  where state.json and control.json are (service: /var/lib/tsnzeek)
  TSNZEEK_LOG_DIR      where Zeek's logs and alerts.log are (service: /var/log/tsnzeek)
  TSNZEEK_WEB_DEBUG    1 for Django's debug pages
"""
import os
import secrets
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BASE_DIR.parent
sys.path.insert(0, str(REPO_ROOT))          # the web interface validates with ids/catalog.py and ids/control.py

BASE = Path(os.environ.get("TSNZEEK_DIR", "~/tsnzeek")).expanduser()
TSNZEEK_CONTROL_DIR = Path(os.environ.get("TSNZEEK_CONTROL_DIR") or BASE / "control")
TSNZEEK_LOG_DIR = Path(os.environ.get("TSNZEEK_LOG_DIR") or BASE / "logs")

DEBUG = os.environ.get("TSNZEEK_WEB_DEBUG") == "1"
SECRET_KEY = os.environ.get("TSNZEEK_WEB_SECRET") or secrets.token_urlsafe(50)   # only signs CSRF tokens
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]", "testserver"]               # same machine only

INSTALLED_APPS = ["console"]
MIDDLEWARE = ["django.middleware.common.CommonMiddleware", "django.middleware.csrf.CsrfViewMiddleware"]
ROOT_URLCONF = "tsnzeek_web.urls"
TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates", "APP_DIRS": True,
              "OPTIONS": {"context_processors": []}}]
WSGI_APPLICATION = "tsnzeek_web.wsgi.application"
DATABASES = {}
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
