from django.urls import path
from .views import LoginView, user_signup_view

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("signup/", user_signup_view, name="user_signup"),
]
