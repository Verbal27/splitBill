from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.models import User
from django.core.mail import send_mail
from rest_framework import serializers
from .models import SplitBill, Expense, Comment, ExpenseAssignment
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from decimal import Decimal
from django.conf import settings


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("username", "email", "password")

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            is_active=False,  # not active until email confirmed
        )
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ("username", "email", "password")

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()
        return instance


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        email = attrs.get("email", "")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                {"email": "User with this email does not exist."}
            )

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)

        attrs["user"] = user
        attrs["uidb64"] = uidb64
        attrs["token"] = token

        return attrs


class SetNewPasswordSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        uidb64 = attrs.get("uidb64")
        token = attrs.get("token")
        password = attrs.get("password")

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            raise serializers.ValidationError({"uidb64": "Invalid UID"})

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError({"token": "Invalid or expired token"})

        attrs["user"] = user
        return attrs

    def save(self, **kwargs):
        user = self.validated_data["user"]
        password = self.validated_data["password"]
        user.set_password(password)
        user.save()
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email"]


class CommentSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)  # show details in response
    text = serializers.CharField()

    class Meta:
        model = Comment
        fields = ["id", "author", "text", "date_created", "split_bill"]
        read_only_fields = ["id", "author", "date_created"]

    def create(self, validated_data):
        request = self.context["request"]
        split_bill = validated_data["split_bill"]
        return Comment.objects.create(
            author=request.user, split_bill=split_bill, text=validated_data["text"]
        )


class ExpenseAssignmentSerializer(serializers.ModelSerializer):
    user = serializers.SlugRelatedField(
        slug_field="username", queryset=User.objects.all()
    )

    class Meta:
        model = ExpenseAssignment
        fields = ["user", "share_amount"]


class ExpenseSerializer(serializers.ModelSerializer):
    assignments = ExpenseAssignmentSerializer(many=True, write_only=True)
    assigned_users = ExpenseAssignmentSerializer(
        many=True, read_only=True, source="expense_assignment"
    )

    class Meta:
        model = Expense
        fields = [
            "id",
            "title",
            "amount",
            "assignments",
            "assigned_users",
            "date_created",
            "split_bill",
        ]

    def validate(self, attrs):
        assignments = self.initial_data.get("assignments", [])
        if assignments:
            total_share = sum(Decimal(str(a["share_amount"])) for a in assignments)
            amount = Decimal(str(attrs.get("amount", 0)))
            if abs(total_share - amount) > Decimal("0.01"):
                raise serializers.ValidationError(
                    {
                        "assignments": f"Sum of shares ({total_share}) must equal the total amount ({amount})."
                    }
                )
        return attrs

    def create(self, validated_data):
        assignments_data = validated_data.pop("assignments", [])
        expense = Expense.objects.create(**validated_data)
        for assignment in assignments_data:
            ExpenseAssignment.objects.create(expense=expense, **assignment)
        return expense


class SplitBillSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    members = UserSerializer(many=True, read_only=True)
    member_usernames = serializers.ListField(
        child=serializers.CharField(), write_only=True, required=False
    )
    expenses = ExpenseSerializer(many=True, read_only=True)
    comments = CommentSerializer(many=True, read_only=True)

    class Meta:
        model = SplitBill
        fields = [
            "id",
            "title",
            "date_created",
            "currency",
            "owner",
            "members",
            "member_usernames",
            "expenses",
            "comments",
            "active",
        ]

    def create(self, validated_data):
        member_usernames = validated_data.pop("member_usernames", [])
        request = self.context.get("request")
        split_bill = SplitBill.objects.create(owner=request.user, **validated_data)

        split_bill.members.add(request.user)

        for username in member_usernames:
            try:
                user = User.objects.get(username=username)
                split_bill.members.add(user)
                pk = split_bill.pk
                domain = get_current_site(request).domain
                link = reverse("split-bill-detail", kwargs={"pk": pk})
                activate_url = f"http://{domain}{link}"

                subject = "Seems you owe someone money :D"
                message = (
                    f"Hi {user.username},\n\n"
                    f"Someone added you to a split bill session.\n"
                    f"View it here: {activate_url}"
                )
                send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])
            except User.DoesNotExist:
                raise serializers.ValidationError(
                    {"member_usernames": f"User '{username}' not found."}
                )

        return split_bill


class AddMemberSerializer(serializers.Serializer):
    username = serializers.CharField()

    def validate_username(self, value):
        try:
            return User.objects.get(username=value)
        except User.DoesNotExist:
            raise serializers.ValidationError(f"User '{value}' does not exist.")

    def save(self, **kwargs):
        split_bill = self.context["split-bill"]
        user = self.validated_data["username"]

        split_bill.members.add(user)

        request = self.context.get("request")
        pk = split_bill.pk
        domain = get_current_site(request).domain
        link = reverse("split-bill-detail", kwargs={"pk": pk})
        url = f"http://{domain}{link}"

        subject = "Seems you owe someone money :D"
        message = (
            f"Hi {user.username},\n\n"
            f"Someone added you to a split bill session.\n"
            f"View it here: {url}"
        )
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])

        return split_bill


class RemoveMemberSerializer(serializers.Serializer):
    username = serializers.CharField()

    def validate_username(self, value):
        try:
            return User.objects.get(username=value)
        except User.DoesNotExist:
            raise serializers.ValidationError(f"User '{value}' does not exist.")
