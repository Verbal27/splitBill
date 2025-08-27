from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .tokens import account_activation_token
from django.core.mail import send_mail
from rest_framework import permissions
from django.urls import reverse


def send_activation_email(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    domain = get_current_site(request).domain
    link = reverse("activate", kwargs={"uidb64": uid, "token": token})
    activate_url = f"http://{domain}{link}"

    subject = "Activate your account"
    message = f"Hi {user.username}, click the link to activate: {activate_url}"
    send_mail(subject, message, None, [user.email])


class IsSplitBillMember(permissions.BasePermission):
    """
    Permission to only allow members (or owner) of a SplitBill to access it.
    """

    def has_object_permission(self, request, view, obj):
        # obj is expected to be a SplitBill or have a split_bill relation
        if hasattr(obj, "members"):  # obj is SplitBill
            return request.user in obj.members.all() or request.user == obj.owner
        elif hasattr(obj, "split_bill"):  # obj is Expense or Comment
            return (
                request.user in obj.split_bill.members.all()
                or request.user == obj.split_bill.owner
            )
        return False
