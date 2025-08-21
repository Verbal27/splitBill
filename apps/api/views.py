from .serializers import (
    RegisterSerializer,
    UserUpdateSerializer,
    ResetPasswordSerializer,
    SetNewPasswordSerializer,
    SplitBillSerializer,
    ExpenseSerializer,
    CommentSerializer,
    AddMemberSerializer,
    RemoveMemberSerializer,
)
from rest_framework import generics, viewsets, permissions, status
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import PermissionDenied
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from .models import SplitBill, Expense, Comment
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from .utils import send_activation_email
from .tokens import account_activation_token


class UserRegister(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            send_activation_email(user, request)
            return Response(
                {"detail": "Check your email to activate your account."},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserActivation(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"detail": "Account activated successfully!"})
        return Response({"detail": "Invalid or expired activation link."}, status=400)


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


class SplitBillCreateView(generics.ListCreateAPIView):
    serializer_class = SplitBillSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return SplitBill.objects.filter(members=user).prefetch_related(
            "members", "expenses", "comments"
        )


class SplitBillDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = SplitBill.objects.all().prefetch_related(
        "members", "expenses", "comments"
    )
    serializer_class = SplitBillSerializer
    permission_classes = [permissions.IsAuthenticated]


class ExpenseListCreateView(generics.ListCreateAPIView):
    queryset = (
        Expense.objects.all()
        .select_related("split_bill")
        .prefetch_related("assignments")
    )
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]


class ExpenseDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = (
        Expense.objects.all()
        .select_related("split_bill", "user")
        .prefetch_related("assignments")
    )
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]


class AddMemberView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AddMemberSerializer

    def post(self, request, pk):
        split_bill = get_object_or_404(SplitBill, pk=pk)

        if request.user != split_bill.owner:
            raise PermissionDenied("Only the splitbill owner can add members.")

        serializer = AddMemberSerializer(
            data=request.data, context={"request": request, "split-bill": split_bill}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"detail": "Member added successfully"},
            status=status.HTTP_201_CREATED,
        )


class RemoveMemberView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = RemoveMemberSerializer

    def post(self, request, pk):
        split_bill = get_object_or_404(SplitBill, pk=pk)

        if split_bill.owner != request.user:
            return Response(
                {"detail": "Only the owner can remove members."},
                status=status.HTTP_403_FORBIDDEN,
            )

        username = request.data.get("username")
        if not username:
            return Response(
                {"detail": "Username is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = get_object_or_404(User, username=username)
        split_bill.members.remove(user)

        return Response(
            {"detail": f"User '{username}' removed successfully."},
            status=status.HTTP_200_OK,
        )


class CommentCreateView(generics.CreateAPIView):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        split_bill = serializer.validated_data["split_bill"]
        if (
            self.request.user != split_bill.owner
            and self.request.user not in split_bill.members.all()
        ):
            raise PermissionDenied("You must be a member of the splitbill to comment.")
        serializer.save(author=self.request.user)
