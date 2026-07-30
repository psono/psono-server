from rest_framework.permissions import BasePermission
from datetime import date


class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    Prevents GETs if read permission is not granted.
    Prevents not GETs if write permissions is not granted.
    """

    PASSWORD_CHANGE_GATE_START_DATE = date(2026, 10, 1)
    PASSWORD_CHANGE_GATE_ALLOWED_URL_NAMES = {
        "authentication_logout",
        "authentication_activate_token",
        "authentication_ga_verify",
        "authentication_duo_verify",
        "authentication_webauthn_verify",
        "authentication_yubikey_otp_verify",
        "authentication_ivalt_verify",
        "user_update",
        "user_ga",
        "user_duo",
        "user_webauthn",
        "user_yubikey_otp",
        "user_ivalt",
    }

    def has_permission(self, request, view):
        resolver_match = getattr(request, "resolver_match", None)
        url_name = resolver_match.url_name if resolver_match else None

        if request.user and request.user.is_authenticated:
            if date.today() >= self.PASSWORD_CHANGE_GATE_START_DATE:
                if getattr(request.user, "require_password_change", False):
                    if url_name not in self.PASSWORD_CHANGE_GATE_ALLOWED_URL_NAMES:
                        return False

        # Allow logout
        if url_name == "authentication_logout" and request.method == "POST":
            return request.user and request.user.is_authenticated

        # bulk-secret-read uses a POST request to read the data
        if url_name == "bulk_secret_read":
            if request.auth and not request.auth.read:
                return False
        elif request.method == "GET" and request.auth and not request.auth.read:
            return False
        elif request.method != "GET" and request.auth and not request.auth.write:
            return False

        return request.user and request.user.is_authenticated
