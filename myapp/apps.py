from django.apps import AppConfig
from django.contrib.auth.signals import user_logged_out


class MyappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myapp'

    def ready(self):
        # Implicitly connect signal handlers decorated with @receiver.
        from . import signals
        # Explicitly connect signal
        user_logged_out.connect(signals._user_logged_out)
