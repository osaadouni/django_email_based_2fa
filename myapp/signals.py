import logging

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django_otp.plugins.otp_email.models import EmailDevice

logger = logging.getLogger(__name__)


@receiver(user_logged_in)
def _user_logged_in(sender, user, request, **kwargs):
    logger.debug(f"==> User has logged in: {user}")
    pass

@receiver(user_logged_out)
def _user_logged_out(sender, user, request, **kwargs):
    logger.debug(f"==> User {user} logged out; delete emaildevice!")
    try:
        EmailDevice.objects.get(user=user).delete()
    except EmailDevice.DoesNotExist:
        logger.exception(f"emaildevice for user {user} does not exist")
    else:
        logger.debug(f"emaildevice for user {user} deleted successfully!")