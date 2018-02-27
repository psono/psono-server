from rest_framework.permissions import BasePermission

class AdminPermission(BasePermission):
    """
    Allows access only to superusers or staff that has the necessary object level permissions.
    """

    def has_permission(self, request, view):
        # TODO implement logic for "is_staff" users that checks permissions on the endpoint / METHOD to allow / deny access
        return request.user and request.user.is_superuser