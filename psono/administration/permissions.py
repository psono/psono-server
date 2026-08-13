from rest_framework.permissions import BasePermission, SAFE_METHODS
from rest_framework.exceptions import PermissionDenied


class AdminPermission(BasePermission):
    """
    Allows access only to superusers or staff that has the necessary object level permissions.
    """

    def has_permission(self, request, view):
        # TODO implement logic for "is_staff" users that checks permissions on the endpoint / METHOD to allow / deny access
        is_admin = request.user and (
            request.user.is_superuser or request.user.is_staff
        )

        if not is_admin:
            return False

        token = request.auth
        api_key = getattr(token, "api_key", None)

        if api_key is not None and api_key.restrict_to_secrets:
            raise PermissionDenied("API_KEY_RESTRICTED_TO_SECRETS")

        if request.method in SAFE_METHODS and token and not token.read:
            return False

        if request.method not in SAFE_METHODS and token and not token.write:
            return False

        return True
