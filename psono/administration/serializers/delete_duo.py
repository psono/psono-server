from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Duo
from .admin_access import AdminCapabilitySerializerMixin


class DeleteDuoSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "users.mfa.delete"

    duo_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        duo_id = attrs.get("duo_id")

        try:
            duo = Duo.objects.get(pk=duo_id)
        except Duo.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(user=duo.user)

        attrs["duo"] = duo

        return attrs
