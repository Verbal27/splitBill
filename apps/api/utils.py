from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .tokens import account_activation_token
from django.core.mail import send_mail
from rest_framework import permissions
from django.conf import settings
from django.urls import reverse


def send_activation_email(user, request):
    try:
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)

        try:
            domain = get_current_site(request).domain
        except Exception:
            domain = "localhost:8000"

        link = reverse("activate-user", kwargs={"uidb64": uid, "token": token})
        activate_url = f"http://{domain}{link}"

        subject = "Activate your account"
        message = f"Hi from SplitBill, click the link to activate: {activate_url}"

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
    except Exception as e:
        import traceback

        print("[Activation Email Error]", traceback.format_exc())


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
