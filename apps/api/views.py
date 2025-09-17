from .serializers import (
    ExpenseUpdateSerializer,
    RegisterSerializer,
    SplitBillMemberUpdateSerializer,
    UserSerializer,
    UserUpdateSerializer,
    ResetPasswordSerializer,
    SetNewPasswordSerializer,
    SplitBillSerializer,
    EqualExpenseSerializer,
    CustomExpenseSerializer,
    PercentageExpenseSerializer,
    ExpenseSerializer,
    CommentSerializer,
    AddMemberSerializer,
    RemoveMemberSerializer,
)
from .utils import IsSplitBillMember, IsSplitBillOwner, send_mailgun_email
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import generics, permissions, status
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_str, force_bytes
from django.core.exceptions import PermissionDenied
from .models import PendingInvitation, SplitBill, Expense, Comment, SplitBillMember
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from .tokens import account_activation_token
from django.contrib.auth.models import User
from rest_framework.views import APIView
from django.urls import reverse


class UserRegister(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()

        pending_invites = PendingInvitation.objects.filter(email=user.email)
        for invite in pending_invites:
            split_bill = invite.split_bill

            member = split_bill.splitbill_members.filter(email=user.email).first()
            if member:
                member.user = user
                member.save()
            else:
                SplitBillMember.objects.create(
                    split_bill=split_bill,
                    user=user,
                    email=user.email,
                    alias=user.username,
                )

            split_bill.members.add(user)

            invite.delete()

        return user

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            self.perform_create(serializer)
            user = serializer.instance

            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = account_activation_token.make_token(user)
            domain = get_current_site(request).domain
            link = reverse("activate-user", kwargs={"uidb64": uid, "token": token})
            activate_url = f"http://{domain}{link}"

            subject = "Activate your SplitBill account"
            message = f"Hi {user.username},\n\nClick here to activate your account:\n{activate_url}"
            send_mailgun_email(subject, message, user.email)

            return Response(
                {"detail": "Check your email to activate your account."},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            import traceback

            print("[Registration Error]", traceback.format_exc())
            return Response(
                {"detail": f"Internal server error during registration.{e}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


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


class UserView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class UpdateUserView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserUpdateSerializer

    def get_queryset(self):
        return User.objects.filter(id=self.request.user.id)

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ResetPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        uidb64 = serializer.validated_data["uidb64"]
        token = serializer.validated_data["token"]

        reset_link = request.build_absolute_uri(
            reverse("reset-password-confirm", kwargs={"uidb64": uidb64, "token": token})
        )

        # Send email via Mailgun
        send_mailgun_email(
            subject="Password Reset Request",
            message=f"Hi {user.username},\n\nClick the link below to reset your password:\n{reset_link}",
            to_email=user.email,
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
    queryset = SplitBill.objects.all()

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
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]


class UpdateSplitBillMemberView(generics.UpdateAPIView):
    serializer_class = SplitBillMemberUpdateSerializer
    permission_classes = [permissions.IsAuthenticated, IsSplitBillOwner]

    def get_queryset(self):
        split_bill_id = self.kwargs["split_bill_id"]
        return SplitBillMember.objects.filter(
            split_bill_id=split_bill_id, split_bill__owner=self.request.user
        )


class EqualExpenseCreateView(generics.CreateAPIView):
    queryset = (
        Expense.objects.all()
        .select_related("split_bill")
        .prefetch_related("assignments")
    )
    serializer_class = EqualExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]


class CustomExpenseCreateView(generics.CreateAPIView):
    queryset = (
        Expense.objects.all()
        .select_related("split_bill")
        .prefetch_related("assignments")
    )
    serializer_class = CustomExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]


class PercentageExpenseCreateView(generics.CreateAPIView):
    queryset = (
        Expense.objects.all()
        .select_related("split_bill")
        .prefetch_related("assignments")
    )
    serializer_class = PercentageExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]


class ExpenseListView(generics.ListAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]

    def get_queryset(self):
        user = self.request.user
        return (
            Expense.objects.filter(split_bill__members__id=user.id)
            .select_related("paid_by", "split_bill")
            .prefetch_related("expense_assignment__user")
        )


class ExpenseDetailView(generics.RetrieveDestroyAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]

    def get_queryset(self):
        return Expense.objects.filter(split_bill__members=self.request.user)


class ExpenseUpdateView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]
    serializer_class = ExpenseUpdateSerializer

    def get_object(self):
        expense = get_object_or_404(Expense, pk=self.kwargs["pk"])
        self.check_object_permissions(self.request, expense)
        return expense

    def patch(self, request, *args, **kwargs):
        expense = self.get_object()
        serializer = self.serializer_class(expense, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": "Expense updated successfully."}, status=status.HTTP_200_OK
        )


class AddMemberView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsSplitBillOwner]
    serializer_class = AddMemberSerializer

    def post(self, request, pk):
        split_bill = get_object_or_404(SplitBill, pk=pk)
        serializer = AddMemberSerializer(
            data=request.data,
            context={"request": request, "split-bill": split_bill},
        )
        serializer.is_valid(raise_exception=True)
        member = serializer.save()
        return Response(
            {
                "detail": "Member added successfully",
                "member": {
                    "id": member.id,
                    "alias": member.alias,
                    "email": member.email,
                    "user": member.user.id if member.user else None,
                },
            },
            status=201,
        )


class RemoveMemberView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsSplitBillOwner]
    serializer_class = RemoveMemberSerializer

    def post(self, request, pk):
        split_bill = get_object_or_404(SplitBill, pk=pk)

        if split_bill.owner != request.user:
            return Response(
                {"detail": "Only the owner can remove members."},
                status=status.HTTP_403_FORBIDDEN,
            )

        alias = request.data.get("alias")
        email = request.data.get("email")

        if not alias and not email:
            return Response(
                {"detail": "Either alias or email is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        member_qs = split_bill.splitbill_members.all()
        if alias:
            member_qs = member_qs.filter(alias=alias)
        if email:
            member_qs = member_qs.filter(email=email)

        if not member_qs.exists():
            return Response(
                {"detail": "No member found with the provided alias/email."},
                status=status.HTTP_404_NOT_FOUND,
            )

        removed_members = []
        for member in member_qs:
            if member.user:
                split_bill.members.remove(member.user)
            removed_members.append(member.display_name())
            member.delete()

        return Response(
            {"detail": f"Removed member(s): {', '.join(removed_members)}"},
            status=status.HTTP_200_OK,
        )


class CommentCreateView(generics.CreateAPIView):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]

    def perform_create(self, serializer):
        split_bill = serializer.validated_data["split_bill"]
        if (
            self.request.user != split_bill.owner
            and self.request.user not in split_bill.members.all()
        ):
            raise PermissionDenied("You must be a member of the splitbill to comment.")
        serializer.save(author=self.request.user)
