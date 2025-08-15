from .serializers import (
    RegisterSerializer,
    UserUpdateSerializer,
    ResetPasswordSerializer,
    SetNewPasswordSerializer,
    SplitBillSerializer,
    ExpenseSerializer,
    CommentSerializer,
    AddMemberSerializer,
)
from rest_framework import generics, viewsets, permissions, status
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from .models import SplitBill, Expense, Comment
from django.core.exceptions import PermissionDenied


class UserRegister(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


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
    queryset = Expense.objects.all().select_related("split_bill", "assigned_to")
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]


class ExpenseDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Expense.objects.all().select_related("split_bill", "assigned_to")
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]


class AddMemberView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, split_bill_id):
        split_bill = get_object_or_404(SplitBill, id=split_bill_id)

        # Only owner can add
        if request.user != split_bill.owner:
            raise PermissionDenied("Only the splitbill owner can add members.")

        serializer = AddMemberSerializer(
            data=request.data, context={"split_bill": split_bill}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Member added successfully"})


class RemoveMemberView(generics.UpdateAPIView):
    queryset = SplitBill.objects.all()
    serializer_class = SplitBillSerializer
    permission_classes = [permissions.IsAuthenticated]

    def update(self, request, *args, **kwargs):
        split_bill = self.get_object()
        if split_bill.owner != request.user:
            return Response(
                {"detail": "Only the owner can remove members."},
                status=status.HTTP_403_FORBIDDEN,
            )
        user_id = request.data.get("user_id")
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )
        split_bill.members.remove(user)
        return Response(SplitBillSerializer(split_bill).data)


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
