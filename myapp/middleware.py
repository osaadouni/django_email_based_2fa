import logging
import datetime

from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_email.models import EmailDevice
from django.http import HttpResponseRedirect
from django.urls import reverse
import django.conf as dj_conf
import django.utils as dj_utils
import django.http as dj_http

from . import utils


logger = logging.getLogger(__name__)

class TwoFactorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the user is authenticated
        logger.info(f"{30*'-'}")
        logger.info(f"{self.__class__.__name__}::__call__(request.path={request.path})")
        logger.info(f"{30*'-'}")
        if request.user.is_authenticated:
            logger.debug(f"[+] user({request.user})  is authenticated")

            # Access the 2FA verification status from the session cookie
            if request.session.get(dj_conf.settings.TWO_FACTOR_AUTH_SESSION_KEY, False):
                # Continue processing for the authenticated user
                logger.debug("[+] session cookie 2fa_verified is set!")
            else:
                # Redirect or handle unverified users as needed
                logger.debug("[-] session cookie 2fa_verified is NOT set!")

                # Check if the user has a 2FA device
                try:
                    email_device = EmailDevice.objects.get(user=request.user)
                    logger.debug(f"==> email_device: {email_device}")
                    if not email_device.confirmed:
                        logger.debug("==> 2FA is NOT confirmed. ")
                        now = dj_utils.timezone.now()
                        logger.debug(f"==> valid_until: {email_device.valid_until}; now: {now}")
                        if now > email_device.valid_until:
                            logger.debug("==> OTP validation period expired")
                            logger.debug('==> Delete old 2FA ')
                            # Delete expired device
                            email_device.delete()
                            logger.debug("==> Setup new 2FA for user.")
                            # setup new 2fa
                            utils.setup_2fa(request)
                            # Redirect to verification page
                            return self._verify_otp_page()

                        logger.debug('==> 2FA token is NOT expired !')

                        # If not confirmed & not expired & not on verify_otp_page then
                        # redirect to otp verification page, else proceed.
                        if not self._current_request_matches_url(request, reverse('verify_otp')):
                            logger.debug("Not on OTP page!. Redirect to otp")
                            return self._verify_otp_page()
                        else:
                            logger.debug("==> Already in OTP verification page URL")
                    else:
                        logger.debug(f"==> 2FA already confirmed, but no 2fa_verified cookie found ")

                        request.session[dj_conf.settings.TWO_FACTOR_AUTH_SESSION_KEY] = True
                        request.session.save()

                        if self._current_request_matches_url(request, reverse('verify_otp')):
                            logger.info(f"==> Redirect to {dj_conf.settings.LOGIN_REDIRECT_URL}")
                            return HttpResponseRedirect(reverse(dj_conf.settings.LOGIN_REDIRECT_URL))

                except EmailDevice.DoesNotExist:
                    logger.debug("==> 2FA device does not exist")
                    # Setup 2FA for the user
                    utils.setup_2fa(request)

                    # Redirect to verification page
                    next_post = request.POST.get('next')
                    next_get = request.GET.get('next')
                    next_param = next_post if next_post is not None else None
                    logger.debug(f"next_post: {next_post}; next_get: {next_get}; next_param: {next_param}")

                    return self._verify_otp_page()

        else:
            logger.debug("[--] User is NOT authenticated")

            if request.session.get(dj_conf.settings.TWO_FACTOR_AUTH_SESSION_KEY, False):
                logger.debug("[--] session cookie 2fa_verified is set!")
            else:
                logger.debug("[--] session cookie 2fa_verified is NOT set")

        logger.debug(f"Proceed with response; request.path: {request.path};")
        logger.debug(f"{100*'='}")
        response = self.get_response(request)
        return response

    @staticmethod
    def _current_request_matches_url(request, url) -> bool:
        logger.debug(f"==> request.path: {request.path}; url: {url}")
        return request.path == url

    @staticmethod
    def _verify_otp_page() -> dj_http.HttpResponseRedirect:
        logger.info("==> Redirect to OTP verification page.")
        return HttpResponseRedirect(reverse('verify_otp'))  # Redirect to OTP verification page
