from django.urls import path
from . import views

app_name = "pages"

urlpatterns = [
    path("guide/", views.guide, name="guide"),
    path("review/", views.review, name="review"),
    path("how-it-works/", views.how_it_works, name="how_it_works"),
    path("roadmap/", views.roadmap, name="roadmap"),
    path("roadmap/subscribe/", views.subscribe, name="subscribe"),
    path(".well-known/security.txt", views.security_txt, name="security_txt"),
]
