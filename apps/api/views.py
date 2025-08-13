from .serializers import (
    RegisterSerializer,
    UserUpdateSerializer,
    ResetPasswordSerializer,
    SetNewPasswordSerializer,
    # SplitBillSerializer,
)
from rest_framework import generics, viewsets, permissions, status
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse


class UserRegister(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


# class UserLogin(generics.GenericAPIView):
#     serializer_class = LoginSerializer

#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(
#             data=request.data, context={"request": request}
#         )
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data["user"]

#         return Response(
#             {
#                 "message": "You're in!",
#                 "user_id": user.pk,
#                 "first_name": user.first_name,
#                 "last_name": user.last_name,
#                 "email": user.email,
#             }
#         )


class UpdateUserView(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserUpdateSerializer

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ResetPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        uidb64 = serializer.validated_data["uidb64"]
        token = serializer.validated_data["token"]

        reset_link = request.build_absolute_uri(
            reverse("reset-password-confirm", kwargs={"uidb64": uidb64, "token": token})
        )

        send_mail(
            subject="Password Reset Request",
            message=f"Click the link to reset your password: {reset_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )

        return Response(
            {"message": "Password reset link sent to your email."},
            status=status.HTTP_200_OK,
        )


class PasswordResetConfirmView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        from django.contrib.auth.tokens import PasswordResetTokenGenerator
        from django.utils.http import urlsafe_base64_decode
        from django.contrib.auth.models import User

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            return Response(
                {"error": "Invalid link"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response(
                {"error": "Token is invalid or expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({"message": "Token is valid"}, status=status.HTTP_200_OK)


class PasswordResetCompleteView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"message": "Password has been reset successfully"},
            status=status.HTTP_200_OK,
        )


# class StartSplitBill(generics.CreateAPIView):
#     serializer_class = SplitBillSerializer
#     permission_classes = [permissions.IsAuthenticated]
