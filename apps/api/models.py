from decimal import Decimal
from datetime import date
from django.conf import settings
from django.db import models, transaction
from django.contrib.auth.models import User


class SplitBill(models.Model):
    title = models.CharField(max_length=255)
    date_created = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(
        User, related_name="owned_split_bills", on_delete=models.CASCADE
    )
    members = models.ManyToManyField(
        User, related_name="member_split_bills", blank=True
    )
    currency = models.CharField(max_length=3)  # e.g., "USD"
    active = models.BooleanField(default=True)

    def __str__(self):
        return self.title


class PendingInvitation(models.Model):
    split_bill = models.ForeignKey(
        SplitBill, on_delete=models.CASCADE, related_name="pending_invitations"
    )
    alias = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    invited_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("split_bill", "alias", "email")

    def __str__(self):
        return (
            f"Pending invitation {self.alias or self.email} to {self.split_bill.title}"
        )


class Expense(models.Model):
    SPLIT_CHOICES = [
        ("equal", "Equal"),
        ("percentage", "Percentage"),
        ("custom", "Custom"),
    ]
    title = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    split_type = models.CharField(max_length=20, choices=SPLIT_CHOICES)
    paid_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="expenses_paid",
    )
    split_bill = models.ForeignKey(
        SplitBill,
        on_delete=models.CASCADE,
        related_name="expenses",
    )
    participants = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through="ExpenseAssignment",
        related_name="participated_expenses",
    )
    date = models.DateField(default=date.today)

    def __str__(self):
        return f"{self.title} ({self.amount})"

    def recalc_assignments(self, new_type, new_assignments=None):
        """
        Recalculate ExpenseAssignment entries safely when changing split_type.
        """
        with transaction.atomic():
            self.expense_assignment.all().delete()

            if new_type == "equal":
                users = new_assignments or self.participants.all()
                normalized_users = []
                for u in users:
                    if isinstance(u, User):
                        normalized_users.append(u)
                    else:
                        try:
                            normalized_users.append(User.objects.get(id=int(u)))
                        except (User.DoesNotExist, ValueError):
                            continue
                if len(normalized_users) < 2:
                    raise ValueError("Equal split requires at least two valid users.")
                share = (self.amount / Decimal(len(normalized_users))).quantize(
                    Decimal("0.01")
                )
                for user in normalized_users:
                    ExpenseAssignment.objects.create(
                        expense=self, user=user, share_amount=share
                    )

            elif new_type == "custom":
                if not isinstance(new_assignments, dict):
                    raise ValueError("Custom split requires dict of user_id -> share")
                for user_id, share in new_assignments.items():
                    try:
                        user = User.objects.get(id=int(user_id))
                    except User.DoesNotExist:
                        continue
                    share_amount = Decimal(str(share)).quantize(Decimal("0.01"))
                    ExpenseAssignment.objects.create(
                        expense=self, user=user, share_amount=share_amount
                    )

            elif new_type == "percentage":
                if not isinstance(new_assignments, dict):
                    raise ValueError(
                        "Percentage split requires dict of user_id -> percent"
                    )
                for user_id, pct in new_assignments.items():
                    try:
                        user = User.objects.get(id=int(user_id))
                    except User.DoesNotExist:
                        continue
                    share_amount = (
                        self.amount * Decimal(str(pct)) / Decimal("100")
                    ).quantize(Decimal("0.01"))
                    ExpenseAssignment.objects.create(
                        expense=self, user=user, share_amount=share_amount
                    )

            self.split_type = new_type
            self.save()


class SplitBillMember(models.Model):
    split_bill = models.ForeignKey(
        SplitBill, related_name="splitbill_members", on_delete=models.CASCADE
    )
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    email = models.EmailField(null=True, blank=True)
    alias = models.CharField(max_length=255, null=True, blank=True)
    invited_at = models.DateTimeField(auto_now_add=True)

    def display_name(self):
        if self.alias:
            return self.alias
        if self.user:
            return self.user.username
        return self.email or "Pending"


class ExpenseAssignment(models.Model):
    expense = models.ForeignKey(
        Expense, on_delete=models.CASCADE, related_name="expense_assignment"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="expense_assignments",
        null=True,  # allow None
        blank=True,
    )
    split_bill_member = models.ForeignKey(
        "SplitBillMember",
        on_delete=models.CASCADE,
        related_name="assignments",
        null=True,  # optional
        blank=True,
    )
    share_amount = models.DecimalField(max_digits=10, decimal_places=2)


class MoneyGiven(models.Model):
    title = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    given_by = models.ForeignKey(
        SplitBillMember, on_delete=models.CASCADE, related_name="money_given_out"
    )
    given_to = models.ForeignKey(
        SplitBillMember, on_delete=models.CASCADE, related_name="money_received"
    )
    split_bill = models.ForeignKey(
        SplitBill,
        on_delete=models.CASCADE,
        related_name="money_given",
    )
    date = models.DateField(default=date.today)

    def __str__(self):
        return f"{self.title} ({self.amount})"


class Comment(models.Model):
    split_bill = models.ForeignKey(
        SplitBill, related_name="comments", on_delete=models.CASCADE
    )
    author = models.ForeignKey(User, related_name="comments", on_delete=models.CASCADE)
    text = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.author.username} on {self.split_bill.title}"


class Balance(models.Model):
    split_bill = models.ForeignKey(
        SplitBill, related_name="balances", on_delete=models.CASCADE
    )
    from_member = models.ForeignKey(
        SplitBillMember,
        related_name="balances_from",
        on_delete=models.CASCADE,
    )
    to_member = models.ForeignKey(
        SplitBillMember,
        related_name="balances_to",
        on_delete=models.CASCADE,
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    active = models.BooleanField(default=True)

    class Meta:
        unique_together = ("split_bill", "from_member", "to_member")

    def __str__(self):
        return f"{self.from_member.alias} → {self.to_member.alias}: {self.amount}"
