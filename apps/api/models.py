from django.db import models
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
    currency = models.CharField(max_length=3)  # e.g., "USD", "EUR", "MDL"
    active = models.BooleanField(default=True)

    def __str__(self):
        return self.title


class Expense(models.Model):
    split_bill = models.ForeignKey(
        SplitBill, related_name="expenses", on_delete=models.CASCADE
    )
    title = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    assigned_to = models.ManyToManyField(
        User, through="ExpenseAssignment", related_name="assigned_expenses"
    )
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} - {self.amount} {self.split_bill.currency}"


class Comment(models.Model):
    split_bill = models.ForeignKey(
        SplitBill, related_name="comments", on_delete=models.CASCADE
    )
    author = models.ForeignKey(User, related_name="comments", on_delete=models.CASCADE)
    text = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.author.username} on {self.split_bill.title}"


class ExpenseAssignemnt(models.Model):
    expense = models.ForeignKey(
        Expense, related_name="expense_assignment", on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        User, related_name="expense_assignment", on_delete=models.CASCADE
    )
    amount = models.DecimalField(default=0.0, max_digits=10, decimal_places=2)

    def __str__(self) -> str:
        return super().__str__()
