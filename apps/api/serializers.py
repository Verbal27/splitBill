from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .models import SplitBill, Expense, Comment, ExpenseAssignment
from django.utils.encoding import force_bytes
from django.contrib.auth.models import User
from rest_framework import serializers
from django.urls import reverse
from decimal import Decimal
from .utils import send_mailgun_email


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
            is_active=False,
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
    assignments = serializers.DictField(
        child=serializers.DecimalField(max_digits=10, decimal_places=2),
        write_only=True,
        required=False,
    )
    assigned_users = serializers.SerializerMethodField(read_only=True)
    paid_by = serializers.SlugRelatedField(
        slug_field="username",
        queryset=User.objects.all(),
        required=False,
        allow_null=True,
    )

    class Meta:
        model = Expense
        fields = [
            "id",
            "title",
            "amount",
            "split_type",
            "assignments",
            "paid_by",
            "assigned_users",
            "date",
            "split_bill",
        ]

    def validate(self, attrs):
        split_bill = attrs.get("split_bill")
        if split_bill and not split_bill.active:
            raise serializers.ValidationError(
                "You cannot add expenses to a closed split bill."
            )

        split_type = attrs.get("split_type", "equal")
        amount = Decimal(str(attrs.get("amount", 0)))
        assignments = self.initial_data.get("assignments", {})

        if split_type == "custom":
            if assignments:
                total_share = sum(Decimal(str(v)) for v in assignments.values())
                if abs(total_share - amount) > Decimal("0.01"):
                    raise serializers.ValidationError(
                        {
                            "assignments": f"Sum of shares ({total_share}) must equal the total amount ({amount})."
                        }
                    )

        elif split_type == "percentage":
            if assignments:
                total_percentage = sum(Decimal(str(v)) for v in assignments.values())
                if abs(total_percentage - Decimal("100")) > Decimal("0.01"):
                    raise serializers.ValidationError(
                        {
                            "assignments": f"Sum of percentages must equal 100 (got {total_percentage})."
                        }
                    )

        elif split_type == "equal":
            usernames = list(assignments.keys())
            if not usernames:
                raise serializers.ValidationError(
                    {"assignments": "Must provide at least one user for equal split."}
                )

        return attrs

    def create(self, validated_data):
        split_bill = validated_data.get("split_bill")
        if not split_bill:
            raise serializers.ValidationError({"split_bill": "SplitBill is required."})

        if "paid_by" not in validated_data or validated_data["paid_by"] is None:
            validated_data["paid_by"] = split_bill.owner

        split_type = validated_data.get("split_type", "equal")
        assignments_data = validated_data.pop("assignments", {})
        expense = Expense.objects.create(**validated_data)
        amount = expense.amount

        try:
            if split_type == "custom":
                for username, share_amount in assignments_data.items():
                    user = User.objects.filter(username=username).first()
                    if not user:
                        continue  # skip invalid users
                    ExpenseAssignment.objects.create(
                        expense=expense, user=user, share_amount=share_amount
                    )

            elif split_type == "percentage":
                for username, percentage in assignments_data.items():
                    user = User.objects.filter(username=username).first()
                    if not user:
                        continue
                    share_amount = (amount * Decimal(str(percentage))) / Decimal("100")
                    ExpenseAssignment.objects.create(
                        expense=expense, user=user, share_amount=share_amount
                    )

            elif split_type == "equal":
                usernames = list(assignments_data.keys())
                if not usernames:
                    usernames = [split_bill.owner.username]  # fallback to owner
                share_amount = amount / max(len(usernames), 1)
                for username in usernames:
                    user = User.objects.filter(username=username).first()
                    if not user:
                        continue
                    ExpenseAssignment.objects.create(
                        expense=expense, user=user, share_amount=share_amount
                    )

        except Exception as e:
            # Log the error if needed
            pass  # prevent crashing the API

        return expense

    def get_assigned_users(self, obj):
        return {
            a.user.username: str(a.share_amount) for a in obj.expense_assignment.all()
        }


class SplitBillSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    members = UserSerializer(many=True, read_only=True)
    members_emails = serializers.ListField(
        child=serializers.EmailField(), write_only=True, required=False
    )
    expenses = ExpenseSerializer(many=True, read_only=True)
    comments = CommentSerializer(many=True, read_only=True)
    balances = serializers.SerializerMethodField()

    class Meta:
        model = SplitBill
        fields = [
            "id",
            "title",
            "date_created",
            "currency",
            "owner",
            "members",
            "members_emails",
            "expenses",
            "comments",
            "balances",
            "active",
        ]

    def create(self, validated_data):
        emails = validated_data.pop("members_emails", [])
        request = self.context.get("request")
        if not request:
            raise serializers.ValidationError(
                {"request": "Request context is required."}
            )

        split_bill = SplitBill.objects.create(owner=request.user, **validated_data)
        split_bill.members.add(request.user)

        for email in set(emails):
            user = User.objects.filter(email=email).first()

            if user:
                # Add existing user to the split bill
                split_bill.members.add(user)
                email = user.email
                greeting = f"Hi {user.username},"
            else:
                # No user yet, still send invitation
                email = email
                greeting = "Hi there,"

            invite_link = request.build_absolute_uri(
                reverse("split-bill-detail", kwargs={"pk": split_bill.pk})
            )

            subject = "You've been invited to a SplitBill session!"
            message = (
                f"{greeting},\n\n"
                f"You've been invited to join a SplitBill session titled '{split_bill.title}'.\n"
                f"Click here to view it: {invite_link}\n\n"
                f"If you don't have an account, please register first."
            )

            try:
                send_mailgun_email(subject, message, email)
            except Exception as e:
                print(f"[ERROR] Failed to send invite email to {email}: {e}")

        return split_bill

    def get_balances(self, obj):
        balances = {}

        assignments = ExpenseAssignment.objects.filter(
            expense__split_bill=obj
        ).select_related("expense", "user")

        for assignment in assignments:
            payer = assignment.expense.paid_by
            debtor = assignment.user
            amount = assignment.share_amount

            if debtor == payer:
                continue

            balances.setdefault(debtor.username, {})
            balances[debtor.username].setdefault(payer.username, Decimal("0.00"))
            balances[debtor.username][payer.username] += amount

        return {
            debtor: {creditor: str(amount) for creditor, amount in creditors.items()}
            for debtor, creditors in balances.items()
        }


class AddMemberSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        return value

    def save(self, **kwargs):
        split_bill = self.context["split-bill"]
        request = self.context.get("request")
        email = self.validated_data["email"]

        user = User.objects.filter(email=email).first()

        if user:
            # Add existing user to the split bill
            split_bill.members.add(user)
            recipient_email = user.email
            greeting = f"Hi {user.username},"
        else:
            # No user yet, still send invitation
            recipient_email = email
            greeting = "Hi there,"

        invite_link = request.build_absolute_uri(
            reverse("split-bill-detail", kwargs={"pk": split_bill.pk})
        )

        subject = "You've been invited to a SplitBill session!"
        message = (
            f"{greeting}\n\n"
            f"You've been invited to join a SplitBill session titled '{split_bill.title}'.\n"
            f"Click here to view it: {invite_link}\n\n"
            f"If you don't have an account yet, please register first using this email address."
        )

        try:
            send_mailgun_email(subject, message, recipient_email)
        except Exception as e:
            print(f"[ERROR] Failed to send invite email to {recipient_email}: {e}")

        return split_bill


class RemoveMemberSerializer(serializers.Serializer):
    username = serializers.CharField()

    def validate_username(self, value):
        try:
            return User.objects.get(username=value)
        except User.DoesNotExist:
            raise serializers.ValidationError(f"User '{value}' does not exist.")
