#!/usr/bin/env python3
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
"""Django's command line: `python web/manage.py runserver` (see web/README.md)."""
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tsnzeek_web.settings")
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
