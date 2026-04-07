from django.urls import path
from . import views

app_name = "scanner"

urlpatterns = [
    path("", views.home, name="home"),
    path("scan/<uuid:pk>/", views.scan_detail, name="scan_detail"),
    path("scan/<uuid:pk>/status/", views.scan_status, name="scan_status"),
    path("scan/<uuid:pk>/rescan/", views.scan_rescan, name="scan_rescan"),
    path("scan/<uuid:pk>/export/txt/", views.scan_export_txt, name="export_txt"),
    path("scan/<uuid:pk>/export/pdf/", views.scan_export_pdf, name="export_pdf"),
]
