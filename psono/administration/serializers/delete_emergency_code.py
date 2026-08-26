from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Emergency_Code
from .admin_access import AdminCapabilitySerializerMixin


class DeleteEmergencyCodeSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "users.recovery.delete"

    emergency_code_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        emergency_code_id = attrs.get("emergency_code_id")

        try:
            emergency_code = Emergency_Code.objects.get(pk=emergency_code_id)
        except Emergency_Code.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(user=emergency_code.user)

        attrs["emergency_code"] = emergency_code

        return attrs
