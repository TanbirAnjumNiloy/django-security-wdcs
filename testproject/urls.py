from django.urls import path
from secapp import views

urlpatterns = [
    path("ping/", views.ping_view, name="ping"),
    path("comment/", views.submit_comment_view, name="submit_comment"),
    path("search/", views.user_search_view, name="user_search"),
    path("profile/save/", views.save_profile_view, name="save_profile"),
    path("profile/<int:pk>/", views.read_profile_view, name="read_profile"),
    path("frame-target/", views.frame_target_view, name="frame_target"),
]
