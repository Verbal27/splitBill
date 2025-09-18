from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.validators import UniqueValidator
from .models import (
    Balance,
    MoneyGiven,
    PendingInvitation,
    SplitBill,
    Expense,
    Comment,
    ExpenseAssignment,
    SplitBillMember,
)
from django.utils.encoding import force_bytes
from django.contrib.auth.models import User
from rest_framework import serializers
from .utils import send_mailgun_email, update_or_create_balances
from django.urls import reverse
from decimal import Decimal


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ("username", "email", "password")

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def create(self, validated_data):
        return User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            is_active=False,
        )


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
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())],
    )

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
    member = serializers.SerializerMethodField()
    share_amount = serializers.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        model = ExpenseAssignment
        fields = ["member", "share_amount"]

    def get_member(self, obj):
        member = obj.split_bill_member
        if member:
            return {
                "id": member.id,
                "alias": member.alias,
                "email": member.email,
                "user": {
                    "id": member.user.id,
                    "username": member.user.username,
                    "email": member.user.email,
                }
                if member.user
                else None,
            }
        return None


class BaseExpenseSerializer(serializers.ModelSerializer):
    paid_by_member = serializers.IntegerField(write_only=True)
    split_type = serializers.CharField(read_only=True)

    class Meta:
        model = Expense
        fields = [
            "id",
            "title",
            "amount",
            "paid_by_member",
            "assignments",
            "date",
            "split_bill",
            "split_type",
        ]

    def validate_paid_by_member(self, value):
        member = SplitBillMember.objects.filter(id=value).first()
        if not member:
            raise serializers.ValidationError(f"Invalid SplitBillMember ID {value}")
        if not member.user:
            raise serializers.ValidationError(
                "Paid by member must be a registered user."
            )
        return member

    def create_assignments(self, expense, assignments):
        """
        Creates ExpenseAssignment objects for given assignments.
        Handles members without linked users by assigning user=None.
        """
        if isinstance(assignments, list):
            # Equal split
            share_amount = (expense.amount / len(assignments)).quantize(Decimal("0.01"))
            for member_id in assignments:
                member = SplitBillMember.objects.filter(id=member_id).first()
                if not member:
                    continue
                ExpenseAssignment.objects.create(
                    expense=expense,
                    user=member.user,  # can be None
                    split_bill_member=member,
                    share_amount=share_amount,
                )
        elif isinstance(assignments, dict):
            # Custom or percentage
            for member_id, value in assignments.items():
                member = SplitBillMember.objects.filter(id=member_id).first()
                if not member:
                    continue
                ExpenseAssignment.objects.create(
                    expense=expense,
                    user=member.user,  # can be None
                    split_bill_member=member,
                    share_amount=Decimal(str(value)).quantize(Decimal("0.01")),
                )
        else:
            raise serializers.ValidationError("Invalid assignments format")


class EqualExpenseSerializer(BaseExpenseSerializer):
    assignments = serializers.ListField(
        child=serializers.IntegerField(), write_only=True
    )

    def create(self, validated_data):
        member_ids = validated_data.pop("assignments")
        paid_by_member = validated_data.pop("paid_by_member")
        paid_by_user = paid_by_member.user  # ensure it's a User

        expense = Expense.objects.create(
            split_type="equal",
            paid_by=paid_by_user,
            **validated_data,
        )
        self.create_assignments(expense, member_ids)
        return expense


class CustomExpenseSerializer(BaseExpenseSerializer):
    assignments = serializers.DictField(
        child=serializers.DecimalField(max_digits=10, decimal_places=2),
        write_only=True,
    )

    def validate(self, attrs):
        assignments = self.initial_data.get("assignments", {})
        total = sum(Decimal(str(v)) for v in assignments.values())
        if abs(total - Decimal(str(attrs.get("amount", 0)))) > Decimal("0.01"):
            raise serializers.ValidationError(
                {"assignments": "Shares must add up to total amount."}
            )
        return attrs

    def create(self, validated_data):
        assignments = validated_data.pop("assignments")
        paid_by_member = validated_data.pop("paid_by_member")
        paid_by_user = paid_by_member.user

        expense = Expense.objects.create(
            split_type="custom",
            paid_by=paid_by_user,
            **validated_data,
        )
        self.create_assignments(expense, assignments)
        return expense


class PercentageExpenseSerializer(BaseExpenseSerializer):
    assignments = serializers.DictField(
        child=serializers.DecimalField(max_digits=5, decimal_places=2),
        write_only=True,
    )

    def validate(self, attrs):
        assignments = self.initial_data.get("assignments", {})
        total = sum(Decimal(str(v)) for v in assignments.values())
        if abs(total - Decimal("100")) > Decimal("0.01"):
            raise serializers.ValidationError(
                {"assignments": "Percentages must add up to 100."}
            )
        return attrs

    def create(self, validated_data):
        assignments = validated_data.pop("assignments")
        paid_by_member = validated_data.pop("paid_by_member")
        paid_by_user = paid_by_member.user
        amount = Decimal(str(validated_data["amount"]))

        # Convert percentages to absolute amounts
        for member_id, pct in assignments.items():
            assignments[member_id] = (
                amount * Decimal(str(pct)) / Decimal("100")
            ).quantize(Decimal("0.01"))

        expense = Expense.objects.create(
            split_type="percentage",
            paid_by=paid_by_user,
            **validated_data,
        )
        self.create_assignments(expense, assignments)
        return expense


class ExpenseUpdateSerializer(serializers.Serializer):
    split_type = serializers.ChoiceField(choices=Expense.SPLIT_CHOICES)
    assignments = serializers.JSONField()

    def validate(self, attrs):
        split_type = attrs.get("split_type")
        assignments = attrs.get("assignments")

        if split_type == "equal" and not isinstance(assignments, list):
            raise serializers.ValidationError(
                "Equal split requires a list of member IDs."
            )
        if split_type in ["custom", "percentage"] and not isinstance(assignments, dict):
            raise serializers.ValidationError(
                f"{split_type.capitalize()} split requires a dict."
            )

        if split_type == "custom":
            total = sum(Decimal(str(v)) for v in assignments.values())
            if abs(total - Decimal(str(self.instance.amount))) > Decimal("0.01"):
                raise serializers.ValidationError("Shares must add up to total amount.")
        elif split_type == "percentage":
            total = sum(Decimal(str(v)) for v in assignments.values())
            if abs(total - Decimal("100")) > Decimal("0.01"):
                raise serializers.ValidationError("Percentages must add up to 100.")
        return attrs

    def update(self, instance, validated_data):
        split_type = validated_data["split_type"]
        assignments = validated_data["assignments"]

        # Delete old assignments
        instance.expense_assignment.all().delete()

        if split_type == "equal":
            share_amount = (instance.amount / len(assignments)).quantize(
                Decimal("0.01")
            )
            for member_id in assignments:
                member = SplitBillMember.objects.filter(id=member_id).first()
                if not member:
                    continue
                ExpenseAssignment.objects.create(
                    expense=instance,
                    split_bill_member=member,
                    user=member.user,  # can be None
                    share_amount=share_amount,
                )

        elif split_type in ["custom", "percentage"]:
            for member_id, value in assignments.items():
                member = SplitBillMember.objects.filter(id=member_id).first()
                if not member:
                    continue
                if split_type == "percentage":
                    value = (
                        instance.amount * Decimal(str(value)) / Decimal("100")
                    ).quantize(Decimal("0.01"))
                else:
                    value = Decimal(str(value)).quantize(Decimal("0.01"))

                ExpenseAssignment.objects.create(
                    expense=instance,
                    split_bill_member=member,
                    user=member.user,  # can be None
                    share_amount=value,
                )

        instance.split_type = split_type
        instance.save()
        return instance


class ExpenseSerializer(serializers.ModelSerializer):
    paid_by = serializers.SerializerMethodField()
    assignments = ExpenseAssignmentSerializer(
        many=True, source="expense_assignment", read_only=True
    )

    class Meta:
        model = Expense
        fields = [
            "id",
            "title",
            "amount",
            "split_type",
            "paid_by",
            "assignments",
            "date",
        ]

    def get_paid_by(self, obj):
        if obj.paid_by:
            member = obj.split_bill.splitbill_members.filter(user=obj.paid_by).first()
            if member:
                return {
                    "id": member.id,
                    "alias": member.alias,
                    "user": {
                        "id": member.user.id,
                        "username": member.user.username,
                        "email": member.user.email,
                    }
                    if member.user
                    else None,
                }
        return None


class MoneyGivenSerializer(serializers.ModelSerializer):
    given_to = serializers.PrimaryKeyRelatedField(
        queryset=SplitBillMember.objects.all()
    )
    given_by = serializers.PrimaryKeyRelatedField(
        queryset=SplitBillMember.objects.all(), required=False, allow_null=True
    )
    split_bill = serializers.PrimaryKeyRelatedField(queryset=SplitBill.objects.all())

    class Meta:
        model = MoneyGiven
        fields = ["id", "title", "amount", "given_by", "given_to", "split_bill", "date"]
        read_only_fields = ["id"]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and not validated_data.get("given_by"):
            user_member = SplitBillMember.objects.filter(
                split_bill=validated_data["split_bill"], user=request.user
            ).first()
            validated_data["given_by"] = user_member

        return super().create(validated_data)


class MoneyGivenDetailSerializer(serializers.ModelSerializer):
    given_by = serializers.SerializerMethodField()
    given_to = serializers.SerializerMethodField()

    class Meta:
        model = MoneyGiven
        fields = ["id", "title", "amount", "given_by", "given_to", "date"]

    def get_given_by(self, obj):
        if obj.given_by:
            return {
                "id": obj.given_by.id,
                "alias": obj.given_by.alias,  # always alias
                "username": obj.given_by.user.username if obj.given_by.user else None,
            }
        return None

    def get_given_to(self, obj):
        if obj.given_to:
            return {
                "id": obj.given_to.id,
                "alias": obj.given_to.alias,  # always alias
                "username": obj.given_to.user.username if obj.given_to.user else None,
            }
        return None


class SplitBillMemberSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = SplitBillMember
        fields = ["id", "user", "email", "alias"]

    def get_user(self, obj):
        if obj.user:
            return {
                "id": obj.user.id,
                "username": getattr(obj.user, "username", None) or "Unregistered",
            }
        return None


class BalanceSerializer(serializers.ModelSerializer):
    from_member = serializers.CharField(source="from_member.alias", read_only=True)
    to_member = serializers.CharField(source="to_member.alias", read_only=True)

    class Meta:
        model = Balance
        fields = ["id", "from_member", "to_member", "amount", "active"]


class SplitBillSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    members = SplitBillMemberSerializer(
        many=True, read_only=True, source="splitbill_members"
    )
    member_inputs = serializers.ListField(
        child=serializers.DictField(), write_only=True, required=False
    )
    expenses = ExpenseSerializer(many=True, read_only=True)
    money_given = serializers.SerializerMethodField()
    comments = serializers.SerializerMethodField()
    balances = BalanceSerializer(many=True, read_only=True)

    class Meta:
        model = SplitBill
        fields = [
            "id",
            "title",
            "date_created",
            "currency",
            "owner",
            "members",
            "member_inputs",
            "expenses",
            "money_given",
            "comments",
            "balances",
            "active",
        ]

    def create(self, validated_data):
        request = self.context.get("request")
        member_inputs = validated_data.pop("member_inputs", [])

        split_bill = SplitBill.objects.create(owner=request.user, **validated_data)

        owner_member = SplitBillMember.objects.create(
            split_bill=split_bill, user=request.user, alias=request.user.username
        )
        split_bill.members.add(request.user)

        for entry in member_inputs:
            email = entry.get("email")
            alias = entry.get("alias") or "Unknown"
            user = None
            if email:
                user = SplitBillMember.objects.filter(email=email).first()
                if not user:
                    user = None

            member = SplitBillMember.objects.create(
                split_bill=split_bill, user=user, email=email, alias=alias
            )
            if user:
                split_bill.members.add(user)
            elif email:
                PendingInvitation.objects.create(
                    split_bill=split_bill, email=email, alias=alias
                )

            if email and request:
                try:
                    invite_link = request.build_absolute_uri(
                        reverse("split-bill-detail", kwargs={"pk": split_bill.pk})
                    )
                    send_mailgun_email(
                        "You've been invited to a SplitBill session!",
                        f"Hi {alias}, join '{split_bill.title}' here: {invite_link}",
                        email,
                    )
                except Exception as e:
                    print(f"[EMAIL ERROR] {e}")

        update_or_create_balances(split_bill)

        return split_bill

    def get_comments(self, obj):
        return CommentSerializer(obj.comments.all(), many=True).data

    def get_money_given(self, obj):
        money_qs = obj.money_given.select_related("given_by", "given_to")
        return MoneyGivenDetailSerializer(money_qs, many=True).data

    def get_balances(self, obj):
        update_or_create_balances(obj)
        active_balances = obj.balances.filter(active=True)
        return [
            {
                "from": b.from_member.alias,
                "to": b.to_member.alias,
                "amount": str(b.amount),
            }
            for b in active_balances
        ]


class SplitBillMemberUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SplitBillMember
        fields = ["id", "email", "alias"]

    def update(self, instance, validated_data):
        request = self.context.get("request")
        email = validated_data.get("email")
        alias = validated_data.get("alias")

        if email:
            instance.email = email
            # Check if the email is already registered
            user = User.objects.filter(email=email).first()
            if user:
                instance.user = user
                instance.split_bill.members.add(user)
            else:
                # Create or update a pending invitation
                PendingInvitation.objects.update_or_create(
                    split_bill=instance.split_bill,
                    email=email,
                    defaults={"alias": alias or instance.alias or ""},
                )

                # Send invite email
                if request:
                    invite_link = request.build_absolute_uri(
                        reverse(
                            "split-bill-detail", kwargs={"pk": instance.split_bill.pk}
                        )
                    )
                    subject = "You've been invited to a SplitBill session!"
                    message = (
                        f"Hi {alias or instance.alias or 'there'},\n\n"
                        f"You've been added to '{instance.split_bill.title}'.\n"
                        f"Click here to view: {invite_link}"
                    )
                    try:
                        send_mailgun_email(subject, message, email)
                    except Exception as e:
                        print(f"[EMAIL ERROR] Failed to send invite to {email}: {e}")

        if alias:
            instance.alias = alias

        instance.save()
        return instance


class AddMemberSerializer(serializers.Serializer):
    alias = serializers.CharField(required=True)
    email = serializers.EmailField(required=False, allow_blank=True)

    def save(self, **kwargs):
        split_bill = self.context["split-bill"]
        request = self.context.get("request")
        alias = self.validated_data["alias"].strip()
        email = self.validated_data.get("email", "").strip() or None

        user = User.objects.filter(email=email).first() if email else None

        existing_member = split_bill.splitbill_members.filter(
            email=email if email else "", alias=alias
        ).first()
        if existing_member:
            return existing_member

        member = SplitBillMember.objects.create(
            split_bill=split_bill,
            user=user,
            alias=alias,
            email=email,
        )

        if not user and email:
            # Create a pending invitation
            PendingInvitation.objects.create(
                split_bill=split_bill, email=email, alias=alias
            )

        if user:
            split_bill.members.add(user)

        if email and request:
            invite_link = request.build_absolute_uri(
                reverse("split-bill-detail", kwargs={"pk": split_bill.pk})
            )
            subject = "You've been invited to a SplitBill session!"
            message = f"Hi {alias or (user.username if user else 'there')},\n\nYou've been invited to join '{split_bill.title}'.\nClick here: {invite_link}"
            try:
                send_mailgun_email(subject, message, email)
            except Exception as e:
                print(f"[ERROR] Failed to send invite email to {email}: {e}")

        return member


class RemoveMemberSerializer(serializers.Serializer):
    alias = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)

    def save(self, **kwargs):
        split_bill = self.context["split-bill"]
        alias = self.validated_data.get("alias")
        email = self.validated_data.get("email")

        member_qs = split_bill.splitbill_members.all()
        if alias:
            member_qs = member_qs.filter(alias=alias)
        if email:
            member_qs = member_qs.filter(email=email)

        removed_members = []
        for member in member_qs:
            if member.user:
                split_bill.members.remove(member.user)
            removed_members.append(member.display_name())
            member.delete()

        return removed_members
