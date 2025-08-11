from django.urls import path, include
from .views import (
    UserRegister,
    UserLogin,
    UserLogout,
    ResetPassword,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    UpdateUserView,
)
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r"users", UpdateUserView)

urlpatterns = [
    path("", include(router.urls)),
    path("register/", UserRegister.as_view(), name="register"),
    path("login/", UserLogin.as_view(), name="login"),
    path("logout/", UserLogout.as_view(), name="logout"),
    path("reset-password/", ResetPassword.as_view(), name="password-reset"),
    path(
        "reset-password-confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="reset-password-confirm",
    ),
    path(
        "reset-password-complete/",
        PasswordResetCompleteView.as_view(),
        name="password-reset-complete",
    ),
]
