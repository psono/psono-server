from rest_framework.permissions import BasePermission


class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    Prevents GETs if read permission is not granted.
    Prevents not GETs if write permissions is not granted.
    """

    def has_permission(self, request, view):

        if request.method == 'GET' and request.auth and not request.auth.read:
            return False
        if request.method != 'GET' and request.auth and not request.auth.write:
            return False

        return request.user and request.user.is_authenticated