# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tsnzeek_web.settings")
application = get_wsgi_application()
