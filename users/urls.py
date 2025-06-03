from django.urls import path
from .views import LoginView, UserSignupView

urlpatterns = [
    path("signup/", UserSignupView.as_view(), name="user-signup"),
    path("login", LoginView.as_view(), name="login"),
]
