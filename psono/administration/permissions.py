from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import SAFE_METHODS, BasePermission

from .utils.access import user_has_administrative_capabilities


class AdminPermission(BasePermission):
    """
    Allows access to superusers and users with active administrative capabilities.
    """

    message = "INSUFFICIENT_PERMISSIONS"

    def has_permission(self, request, view):
        is_admin = user_has_administrative_capabilities(request.user)

        if not is_admin:
            return False

        token = request.auth
        api_key = getattr(token, "api_key", None)

        if api_key is not None and api_key.restrict_to_secrets:
            raise PermissionDenied("API_KEY_RESTRICTED_TO_SECRETS")

        if api_key is not None and not api_key.allow_admin_access:
            raise PermissionDenied("API_KEY_SESSION_NOT_ALLOWED")

        if request.user.is_superuser and api_key is None:
            return True

        if request.method in SAFE_METHODS and token and not token.read:
            return False

        if request.method not in SAFE_METHODS and token and not token.write:
            return False

        return True
