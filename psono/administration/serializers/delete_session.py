from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Token
from .admin_access import AdminCapabilitySerializerMixin


class DeleteSessionSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "users.sessions.delete"

    session_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        session_id = attrs.get("session_id")

        try:
            token = Token.objects.get(id=session_id)
        except Token.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(user=token.user)

        attrs["token"] = token

        return attrs
