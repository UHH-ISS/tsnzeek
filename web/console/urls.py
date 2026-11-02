# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("api/state", views.api_state, name="api_state"),
    path("api/rule", views.api_rule, name="api_rule"),
    path("api/config", views.api_config, name="api_config"),
    path("api/reset", views.api_reset, name="api_reset"),
    path("api/logs", views.api_logs, name="api_logs"),
]
