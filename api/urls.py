from django.urls import path, include
from .views import Register, Login, Logout, ResetPassword, PasswordResetCompleteView, PasswordResetConfirmView
from rest_framework.routers import DefaultRouter
from .views import UpdateUserView

router = DefaultRouter()
router.register(r'users', UpdateUserView)

urlpatterns = [
    path('', include(router.urls)),
    path('register/', Register.as_view(), name="register"),
    path('login/', Login.as_view(), name="login"),
    path('logout/', Logout.as_view(), name="logout"),
    path('reset-password/', ResetPassword.as_view(), name='password-reset'),
    path('reset-password-confirm/<uidb64>/<token>/',
         PasswordResetConfirmView.as_view(), name='reset-password-confirm'),
    path('reset-password-complete/', PasswordResetCompleteView.as_view(),
         name='password-reset-complete'),

]
