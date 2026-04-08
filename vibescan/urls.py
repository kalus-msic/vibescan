from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("scanner.urls")),
    path("", include("pages.urls")),
    path("dependencies/", include("dependencies.urls")),
]
