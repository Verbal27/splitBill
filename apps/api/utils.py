from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

from .tokens import account_activation_token


def send_activation_email(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    domain = get_current_site(request).domain
    link = reverse("activate", kwargs={"uidb64": uid, "token": token})
    activate_url = f"http://{domain}{link}"

    subject = "Activate your account"
    message = f"Hi {user.username}, click the link to activate: {activate_url}"
    send_mail(subject, message, None, [user.email])
