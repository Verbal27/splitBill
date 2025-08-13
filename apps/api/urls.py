from django.urls import path, include
from .views import (
    UserRegister,
    ResetPassword,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    UpdateUserView,
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r"users", UpdateUserView)

urlpatterns = [
    path("", include(router.urls)),
    path("register/", UserRegister.as_view(), name="register"),
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
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
