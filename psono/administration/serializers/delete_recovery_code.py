from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Recovery_Code
from .admin_access import AdminCapabilitySerializerMixin


class DeleteRecoveryCodeSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "users.recovery.delete"

    recovery_code_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        recovery_code_id = attrs.get("recovery_code_id")

        try:
            recovery_code = Recovery_Code.objects.get(pk=recovery_code_id)
        except Recovery_Code.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(user=recovery_code.user)

        attrs["recovery_code"] = recovery_code

        return attrs
