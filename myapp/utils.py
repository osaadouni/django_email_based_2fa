import logging

import django.http as dj_http
import django_otp.plugins.otp_email.models as otp_email_models
import django.core.mail as dj_mail
import django.conf as dj_conf


logger = logging.getLogger(__name__)


def setup_2fa(request: dj_http.HttpRequest) -> None:
    logger.debug("setup_2fa()")
    # If no 2FA device exists, create one and send an OTP via email
    # email_device = otp_email_models.EmailDevice.objects.create(
    #     user=request.user, confirmed=False
    # )
    # email_device, _ = otp_email_models.EmailDevice.objects.get_or_create(user=request.user)
    #
    # Create a new 2FA device of update the existing one for the user.
    email_device, created = otp_email_models.EmailDevice.objects.update_or_create(
        user=request.user, defaults={'confirmed': False}
    )

    # generate a token and send it to the user
    email_device.generate_challenge()

    logger.debug(f"[+] ==> new OTP token: {email_device.token}; valid_until: {email_device.valid_until}")

    # OR manullay call the email sending function
    # send_mail(email_device)

def send_mail(email_device) -> bool:
    # Generate token
    email_device.generate_token()
    otp_token = email_device.token
    # Send email
    logger.debug(f"send email with otp_token: {otp_token}")
    return dj_mail.send_mail(
        'Your OTP for Two-Factor Authentication',
        f'Your OTP token is: {otp_token}',
        dj_conf.settings.DEFAULT_EMAIL_FROM,
        [email_device.user.email],
        fail_silently=False,
    )