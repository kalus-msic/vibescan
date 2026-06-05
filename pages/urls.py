from django.urls import path
from . import views

app_name = "pages"

urlpatterns = [
    path("guide/", views.guide, name="guide"),
    path("guide/tools/", views.guide_tools, name="guide_tools"),
    path("guide/prompts/", views.guide_prompts, name="guide_prompts"),
    path("guide/topics/", views.guide_topics, name="guide_topics"),
    path("review/", views.review, name="review"),
    path("how-it-works/", views.how_it_works, name="how_it_works"),
    path("roadmap/", views.roadmap, name="roadmap"),
    path("roadmap/subscribe/", views.subscribe, name="subscribe"),
    path(".well-known/security.txt", views.security_txt, name="security_txt"),
    path("privacy/", views.privacy, name="privacy"),
    path("terms/", views.terms, name="terms"),
]
