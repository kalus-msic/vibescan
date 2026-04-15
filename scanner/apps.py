import logging
from django.apps import AppConfig

logger = logging.getLogger("auth")


class ScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanner'

    def ready(self):
        from django.contrib.auth.signals import user_logged_in, user_login_failed
        user_logged_in.connect(_on_login_success)
        user_login_failed.connect(_on_login_failed)


def _on_login_success(sender, request, user, **kwargs):
    ip = request.META.get("HTTP_X_REAL_IP") or request.META.get("REMOTE_ADDR")
    logger.warning("LOGIN OK: user=%s ip=%s", user.username, ip)


def _on_login_failed(sender, credentials, request, **kwargs):
    ip = request.META.get("HTTP_X_REAL_IP") or request.META.get("REMOTE_ADDR") if request else "unknown"
    username = credentials.get("username", "unknown")
    logger.warning("LOGIN FAILED: user=%s ip=%s", username, ip)
