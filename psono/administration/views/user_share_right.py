from django.conf import settings
from django.core.cache import cache
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.serializers import Serializer
from restapi.authentication import TokenAuthentication

from ..app_settings import (
    DeleteUserShareRightSerializer,
    UpdateUserShareRightSerializer,
)
from ..permissions import AdminPermission


class UserShareRightView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    http_method_names = ["put", "delete", "options"]

    def get_serializer_class(self):
        if self.request.method == "PUT":
            return UpdateUserShareRightSerializer
        if self.request.method == "DELETE":
            return DeleteUserShareRightSerializer
        return Serializer

    def put(self, request, *args, **kwargs):
        """Update the permissions of an existing direct user share right."""
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user_share_right = serializer.validated_data["user_share_right"]
        update_fields = []
        for permission in ("read", "write", "grant"):
            if permission in serializer.validated_data:
                setattr(
                    user_share_right, permission, serializer.validated_data[permission]
                )
                update_fields.append(permission)
        if update_fields:
            user_share_right.save(update_fields=[*update_fields, "write_date"])

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """Delete a direct user share right without deleting the share itself."""
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user_share_right = serializer.validated_data["user_share_right"]
        user_id = user_share_right.user_id
        user_share_right.delete()
        if settings.CACHE_ENABLE:
            cache.delete("psono_user_status_" + str(user_id))

        return Response({}, status=status.HTTP_200_OK)
