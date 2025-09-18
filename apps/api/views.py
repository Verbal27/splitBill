from .serializers import (
    BalanceSerializer,
    ExpenseUpdateSerializer,
    MoneyGivenSerializer,
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
from .models import (
    Balance,
    PendingInvitation,
    SplitBill,
    Expense,
    Comment,
    SplitBillMember,
    MoneyGiven,
)
from .utils import (
    IsSplitBillMember,
    IsSplitBillOwner,
    send_mailgun_email,
    update_or_create_balances,
)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import generics, permissions, status
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_str, force_bytes
from django.core.exceptions import PermissionDenied
from drf_spectacular.utils import extend_schema
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from .tokens import account_activation_token
from django.contrib.auth.models import User
from rest_framework.views import APIView
from django.urls import reverse


@extend_schema(tags=["user-register"])
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


@extend_schema(tags=["user-activation"])
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


@extend_schema(tags=["users"])
class UserView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


@extend_schema(tags=["users"])
class UpdateUserView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserUpdateSerializer

    @extend_schema(tags=["users"])
    def get_queryset(self):
        return User.objects.filter(id=self.request.user.id)

    @extend_schema(tags=["users"])
    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)


@extend_schema(tags=["users"])
class ResetPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.AllowAny]

    @extend_schema(tags=["reset_password"])
    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)

            user = serializer.validated_data["user"]
            uidb64 = serializer.validated_data["uidb64"]
            token = serializer.validated_data["token"]

            from urllib.parse import quote

            link = reverse(
                "reset-password-confirm",
                kwargs={"uidb64": quote(uidb64), "token": quote(token)},
            )
            reset_link = request.build_absolute_uri(link)

            send_mailgun_email(
                subject="Password Reset Request",
                message=f"Hi {user.username},\n\nClick the link below to reset your password:\n{reset_link}",
                recipient=user.email,
            )

            return Response(
                {"message": "Password reset link sent to your email."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            import traceback

            print("[RESET PASSWORD ERROR]", traceback.format_exc())
            return Response(
                {"detail": "Internal server error during password reset."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


@extend_schema(tags=["users"])
class PasswordResetConfirmView(generics.GenericAPIView):
    @extend_schema(tags=["reset_password"])
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


@extend_schema(tags=["users"])
class PasswordResetCompleteView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    @extend_schema(tags=["reset_password"])
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


@extend_schema(tags=["transactions/expenses"])
class EqualExpenseCreateView(generics.CreateAPIView):
    queryset = (
        Expense.objects.all()
        .select_related("split_bill")
        .prefetch_related("assignments")
    )
    serializer_class = EqualExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        expense = serializer.save()
        update_or_create_balances(expense.split_bill)


@extend_schema(tags=["transactions/expenses"])
class CustomExpenseCreateView(generics.CreateAPIView):
    queryset = (
        Expense.objects.all()
        .select_related("split_bill")
        .prefetch_related("assignments")
    )
    serializer_class = CustomExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        expense = serializer.save()
        update_or_create_balances(expense.split_bill)


@extend_schema(tags=["transactions/expenses"])
class PercentageExpenseCreateView(generics.CreateAPIView):
    queryset = (
        Expense.objects.all()
        .select_related("split_bill")
        .prefetch_related("assignments")
    )
    serializer_class = PercentageExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        expense = serializer.save()
        update_or_create_balances(expense.split_bill)


@extend_schema(tags=["transactions/expenses"])
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


@extend_schema(tags=["transactions/expenses"])
class ExpenseDetailView(generics.RetrieveDestroyAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]

    def get_queryset(self):
        return Expense.objects.filter(split_bill__members=self.request.user)


@extend_schema(tags=["transactions/expenses"])
class ExpenseUpdateView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]
    serializer_class = ExpenseUpdateSerializer

    def patch(self, request, pk):
        expense = get_object_or_404(Expense, pk=pk)
        self.check_object_permissions(request, expense)
        serializer = self.serializer_class(expense, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        update_or_create_balances(expense.split_bill)
        return Response({"detail": "Expense updated successfully."}, status=200)


@extend_schema(tags=["transactions/money_given"])
class MoneyGivenCreateView(generics.ListCreateAPIView):
    serializer_class = MoneyGivenSerializer
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]

    def perform_create(self, serializer):
        expense = serializer.save()
        update_or_create_balances(expense.split_bill)

    def get_queryset(self):
        user = self.request.user
        return MoneyGiven.objects.filter(split_bill__members=user).select_related(
            "given_by", "given_to", "split_bill"
        )


@extend_schema(tags=["transactions/money_given"])
class MoneyGivenDetailView(generics.RetrieveDestroyAPIView):
    serializer_class = MoneyGivenSerializer
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]

    def get_queryset(self):
        return MoneyGiven.objects.filter(split_bill__members=self.request.user)


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


class BalanceListView(generics.ListAPIView):
    serializer_class = BalanceSerializer
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]

    @extend_schema(tags=["balances"])
    def get_queryset(self):
        split_bill_id = self.kwargs["split_bill_id"]
        return Balance.objects.filter(split_bill_id=split_bill_id, active=True)


class BalanceSettleView(generics.UpdateAPIView):
    serializer_class = BalanceSerializer
    permission_classes = [permissions.IsAuthenticated, IsSplitBillMember]

    def get_queryset(self):
        split_bill_id = self.kwargs.get("split_bill_id")
        return Balance.objects.filter(split_bill_id=split_bill_id)

    def get_object(self):
        balance_id = self.kwargs.get("balance_id")
        if not balance_id:
            raise ValueError("Balance ID not provided in URL.")
        balance = get_object_or_404(self.get_queryset(), pk=balance_id)
        return balance

    def patch(self, request, *args, **kwargs):
        try:
            balance = self.get_object()
            active = request.data.get("active", False)
            balance.active = active
            balance.save()
            return Response({"detail": "Balance settled."}, status=status.HTTP_200_OK)
        except Exception as e:
            import traceback

            print("[BALANCE PATCH ERROR]", traceback.format_exc())
            return Response(
                {"detail": f"Internal server error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
