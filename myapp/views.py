import logging

from django.shortcuts import render, redirect
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.decorators import otp_required
import django.conf as dj_conf
from django.urls import reverse
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages


logger = logging.getLogger(__name__)


def index(request):
    return render(request, 'myapp/index.html')


def is_2fa_authenticated(user):
    # Check if the user has set up two-factor authentication
    logger.debug(f"is_2fa_authenticated({user})")
    return EmailDevice.objects.filter(user=user, confirmed=True).exists()
    # return EmailDevice.objects.filter(user=user).exists()

@login_required
@user_passes_test(is_2fa_authenticated)
def protected_view(request):
    return render(request, 'myapp/protected_view.html')


@login_required
@user_passes_test(is_2fa_authenticated)
def input_module(request):
    return render(request, 'myapp/input_module.html')

@login_required
def verify_otp(request):
    logger.debug('------------------')
    logger.debug("verify_otp()")
    logger.debug('------------------')
    if request.method == 'POST':
        next = request.POST.get('next')
        otp_token = request.POST.get('otp_token')
        logger.debug(f"==> otp_token: {otp_token}; next: {next}")
        device = EmailDevice.objects.get(user=request.user)
        if device.verify_token(otp_token):
            logger.info("Token is verified")
            device.confirmed = True
            device.save()

            # set 2FA session cookie
            request.session[dj_conf.settings.TWO_FACTOR_AUTH_SESSION_KEY] = True

            # Redirect the user to their intended page
            logger.info("Redirect to indented page!!")
            if (next := request.POST.get("next")):
                logger.debug(f"=> next: {next}")
                return redirect(next)
            redirect_to = "/admin/" if request.user.is_superuser else reverse("protected_view")
            logger.debug(f"=> redirect_to: {redirect_to}")
            return redirect(redirect_to)
        else:
            # Handle incorrect OTP token
            logger.info("Incorrect OTP token!!!")
            messages.error(request, "Invalid OTP token")
            # return redirect(reverse('protected_view'))
    logger.debug("Render verify_otp page!")
    return render(request, 'myapp/verify_otp.html')  # Create a template for OTP verification