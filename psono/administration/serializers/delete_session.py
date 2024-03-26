from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Token

class DeleteSessionSerializer(serializers.Serializer):
    session_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        session_id = attrs.get('session_id')

        try:
            token = Token.objects.get(id=session_id)
        except Token.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['token'] = token

        return attrs
