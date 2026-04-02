from django.urls import path
from . import views

app_name = "pages"

urlpatterns = [
    path("guide/", views.guide, name="guide"),
    path("jak-to-funguje/", views.how_it_works, name="how_it_works"),
]
