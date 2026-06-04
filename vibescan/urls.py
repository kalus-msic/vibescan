from django.contrib import admin
from django.urls import path, include
from django.views.static import serve
from django.conf import settings
from pages.views import sitemap_xml, robots_txt

urlpatterns = [
    path("admin/", admin.site.urls),
    path("favicon.svg", serve, {"document_root": settings.STATICFILES_DIRS[0], "path": "favicon.svg"}),
    path("sitemap.xml", sitemap_xml, name="sitemap_xml"),
    path("robots.txt", robots_txt, name="robots_txt"),
    path("", include("scanner.urls")),
    path("", include("pages.urls")),
    path("dependencies/", include("dependencies.urls")),
]
