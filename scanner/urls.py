from django.urls import path
from . import views

app_name = "scanner"

urlpatterns = [
    path("", views.home, name="home"),
    path("scan/<uuid:pk>/", views.scan_detail, name="scan_detail"),
    path("scan/<uuid:pk>/status/", views.scan_status, name="scan_status"),
]
