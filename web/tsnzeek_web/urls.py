# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
from django.urls import include, path

urlpatterns = [path("", include("console.urls"))]
