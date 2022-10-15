from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Webauthn

class DeleteWebauthnSerializer(serializers.Serializer):

    webauthn_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        webauthn_id = attrs.get('webauthn_id')

        try:
            webauthn = Webauthn.objects.get(pk=webauthn_id, user=self.context['request'].user)
        except Webauthn.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        webauthn_count = Webauthn.objects.filter(user=self.context['request'].user, active=True).count()



        attrs['webauthn'] = webauthn
        attrs['webauthn_count'] = webauthn_count

        return attrs