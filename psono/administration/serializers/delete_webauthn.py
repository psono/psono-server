from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Webauthn
from .admin_access import AdminCapabilitySerializerMixin


class DeleteWebAuthnSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "users.mfa.delete"

    webauthn_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        webauthn_id = attrs.get("webauthn_id")

        try:
            webauthn = Webauthn.objects.get(pk=webauthn_id)
        except Webauthn.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(user=webauthn.user)

        attrs["webauthn"] = webauthn

        return attrs
