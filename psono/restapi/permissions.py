from rest_framework.permissions import BasePermission
from datetime import date


class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    Prevents GETs if read permission is not granted.
    Prevents not GETs if write permissions is not granted.
    """

    PASSWORD_CHANGE_GATE_START_DATE = date(2026, 10, 1)
    PASSWORD_CHANGE_GATE_ALLOWED_PATHS = {
        "/authentication/logout/",
        "/authentication/activate-token/",
        "/authentication/ga-verify/",
        "/authentication/duo-verify/",
        "/authentication/webauthn-verify/",
        "/authentication/yubikey-otp-verify/",
        "/authentication/ivalt-verify/",
        "/user/update/",
        "/user/ga/",
        "/user/duo/",
        "/user/webauthn/",
        "/user/yubikey-otp/",
        "/user/ivalt/",
    }

    def has_permission(self, request, view):
        path = request.path

        if request.user and request.user.is_authenticated:
            if date.today() >= self.PASSWORD_CHANGE_GATE_START_DATE:
                if getattr(request.user, "require_password_change", False):
                    if path not in self.PASSWORD_CHANGE_GATE_ALLOWED_PATHS:
                        return False

        # Allow logout
        if path == "/authentication/logout/" and request.method == "POST":
            return request.user and request.user.is_authenticated

        # bulk-secret-read uses a POST request to read the data
        if path == "/bulk-secret-read/" and request.auth and not request.auth.read:
            return False

        if request.method == "GET" and request.auth and not request.auth.read:
            return False
        if request.method != "GET" and request.auth and not request.auth.write:
            return False

        return request.user and request.user.is_authenticated
