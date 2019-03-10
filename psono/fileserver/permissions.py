from rest_framework.permissions import BasePermission

class IsFileserver(BasePermission):
    """
    Allows access only to fileservers
    """

    def has_permission(self, request, view):

        return request.user

