from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Ivalt
from .admin_access import AdminCapabilitySerializerMixin


class DeleteIvaltSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "users.mfa.delete"

    ivalt_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        ivalt_id = attrs.get("ivalt_id")

        try:
            ivalt = Ivalt.objects.get(pk=ivalt_id)
        except Ivalt.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(user=ivalt.user)

        attrs["ivalt"] = ivalt

        return attrs
