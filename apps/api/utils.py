from decimal import Decimal
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

from apps.api.models import Balance, ExpenseAssignment, MoneyGiven
from .tokens import account_activation_token
from django.core.mail import send_mail
from rest_framework import permissions
from django.conf import settings
from django.urls import reverse
from django.db import transaction
import threading
import requests


def send_email_async(subject, message, recipient_list):
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list)


def send_activation_email(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    domain = get_current_site(request).domain
    link = reverse("activate-user", kwargs={"uidb64": uid, "token": token})
    activate_url = f"http://{domain}{link}"

    subject = "Activate your account"
    message = f"Hi {user.username}, click the link to activate: {activate_url}"

    threading.Thread(
        target=send_email_async, args=(subject, message, [user.email])
    ).start()


def send_mailgun_email(subject, message, recipient):
    response = requests.post(
        f"https://api.mailgun.net/v3/{settings.MAILGUN_DOMAIN}/messages",
        auth=("api", settings.MAILGUN_API_KEY),
        data={
            "from": f"SplitBill <{settings.DEFAULT_FROM_EMAIL}>",
            "to": [recipient],
            "subject": subject,
            "text": message,
        },
    )
    if response.status_code != 200:
        raise Exception(f"Mailgun error: {response.text}")
    return response


class IsSplitBillMember(permissions.BasePermission):
    """
    Permission to only allow members (or owner) of a SplitBill to access it.
    """

    def has_object_permission(self, request, view, obj):
        if hasattr(obj, "members"):  # obj is SplitBill
            return (
                obj.members.filter(id=request.user.id).exists()
                or request.user == obj.owner
            )
        elif hasattr(obj, "split_bill"):
            return (
                obj.split_bill.members.filter(id=request.user.id).exists()
                or request.user == obj.split_bill.owner
            )
        return False


class IsSplitBillOwner(permissions.BasePermission):
    """
    Permission to only allow owner of splitbill to perform an action.
    """

    def has_object_permission(self, request, view, obj):
        if hasattr(obj, "owner"):
            return request.user == obj.owner
        elif hasattr(obj, "split_bill"):
            return request.user == obj.split_bill.owner
        return False


def update_or_create_balances(split_bill):
    """
    Calculate balances for a SplitBill, update existing records, and create new ones.
    Balances are netted between members to avoid duplication.
    """
    members = split_bill.splitbill_members.all()
    balances_dict = {m.alias: {} for m in members}

    assignments = ExpenseAssignment.objects.filter(
        expense__split_bill=split_bill
    ).select_related("expense", "split_bill_member")

    for a in assignments:
        debtor = a.split_bill_member
        payer_user = a.expense.paid_by
        if not debtor or not payer_user or not a.share_amount:
            continue

        payer_member = split_bill.splitbill_members.filter(user=payer_user).first()
        if not payer_member or debtor.alias == payer_member.alias:
            continue

        balances_dict[debtor.alias].setdefault(payer_member.alias, Decimal("0.00"))
        balances_dict[debtor.alias][payer_member.alias] += a.share_amount

    money_qs = MoneyGiven.objects.filter(split_bill=split_bill).select_related(
        "given_by", "given_to"
    )
    for mg in money_qs:
        giver = mg.given_by
        receiver = mg.given_to
        if not giver or not receiver or giver.alias == receiver.alias:
            continue

        balances_dict[receiver.alias].setdefault(giver.alias, Decimal("0.00"))
        balances_dict[receiver.alias][giver.alias] += mg.amount

    cleaned_balances = {}
    for debtor, creditors in balances_dict.items():
        for creditor, amount in creditors.items():
            if creditor in balances_dict and debtor in balances_dict[creditor]:
                net = amount - balances_dict[creditor][debtor]
                if net > 0:
                    cleaned_balances.setdefault(debtor, {})[creditor] = net
                elif net < 0:
                    cleaned_balances.setdefault(creditor, {})[debtor] = -net
                balances_dict[creditor].pop(debtor, None)
            else:
                cleaned_balances.setdefault(debtor, {})[creditor] = amount

    with transaction.atomic():
        split_bill.balances.update(active=False)

        for debtor_alias, creditors in cleaned_balances.items():
            debtor_member = split_bill.splitbill_members.get(alias=debtor_alias)
            for creditor_alias, amount in creditors.items():
                creditor_member = split_bill.splitbill_members.get(alias=creditor_alias)
                if amount <= 0:
                    continue

                Balance.objects.update_or_create(
                    split_bill=split_bill,
                    from_member=debtor_member,
                    to_member=creditor_member,
                    defaults={"amount": amount, "active": True},
                )
