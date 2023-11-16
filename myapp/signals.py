import logging

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django_otp.plugins.otp_email.models import EmailDevice

from . import utils

logger = logging.getLogger(__name__)


@receiver(user_logged_in)
def _user_logged_in(sender, user, request, **kwargs):

    logger.debug(f"[SIGNAL-user_logged_in] ==> User has logged in: {user};  request.user: {request.user}")

    # setup new 2fa
    utils.setup_2fa(request)


@receiver(user_logged_out)
def _user_logged_out(sender, user, request, **kwargs):
    logger.debug(f"[SIGNAL-user_logged_out] ==> User {user} logged out")
    logger.debug(f"[SIGNAL-user_logged_out] ==> Delete emaildevice {user}")
    try:
        EmailDevice.objects.get(user=user).delete()
    except EmailDevice.DoesNotExist:
        logger.exception(f"emaildevice for user {user} does not exist")
    else:
        logger.debug(f"emaildevice for user {user} deleted successfully!")