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
    path("scan/<uuid:pk>/finding/<str:finding_id>/dismiss/", views.dismiss_finding, name="dismiss_finding"),
    path("scan/<uuid:pk>/finding/<str:finding_id>/restore/", views.restore_finding, name="restore_finding"),
    path("scan/<uuid:pk>/accessibility-classification/", views.set_accessibility_classification, name="set_accessibility_classification"),
    path("scan/<uuid:pk>/deep-status/", views.deep_scan_status, name="deep_status"),
    path("scan/<uuid:pk>/deep-scan/retry/", views.deep_scan_retry, name="deep_retry"),
]
