from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Webauthn

class DeleteWebAuthnSerializer(serializers.Serializer):
    webauthn_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        webauthn_id = attrs.get('webauthn_id')

        try:
            webauthn = Webauthn.objects.get(pk=webauthn_id)
        except Webauthn.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['webauthn'] = webauthn

        return attrs
