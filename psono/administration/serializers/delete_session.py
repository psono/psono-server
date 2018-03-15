from django.utils.translation import ugettext_lazy as _
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
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['token'] = token

        return attrs
