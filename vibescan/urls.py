from django.contrib import admin
from django.urls import path, include
from django.views.static import serve
from django.conf import settings

urlpatterns = [
    path("admin/", admin.site.urls),
    path("favicon.svg", serve, {"document_root": settings.STATICFILES_DIRS[0], "path": "favicon.svg"}),
    path("", include("scanner.urls")),
    path("", include("pages.urls")),
    path("dependencies/", include("dependencies.urls")),
]
