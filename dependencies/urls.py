from django.urls import path
from . import views

app_name = "dependencies"

urlpatterns = [
    path("check/", views.check_dependencies, name="check"),
]
