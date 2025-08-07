from django.urls import path, include
from .views import Register, Login, Logout
from rest_framework.routers import DefaultRouter
from .views import UpdateUserView

router = DefaultRouter()
router.register(r'users', UpdateUserView)

urlpatterns = [
    path('', include(router.urls)),
    path('register/', Register.as_view(), name="register"),
    path('login/', Login.as_view(), name="login"),
    path('logout/', Logout.as_view(), name="logout")
]
