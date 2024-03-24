from rest_framework import serializers, exceptions
from django.core.exceptions import ValidationError

from ..utils import user_has_rights_on_secret

from ..models import Secret

class ReadSecretSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        secret_id = self.context['request'].parser_context['kwargs'].get('secret_id', False)

        if not secret_id:
            msg = 'SECRET_ID_NOT_PROVIDED'
            raise exceptions.ValidationError(msg)

        try:
            secret = Secret.objects.get(pk=secret_id)
        except ValidationError:
            msg = 'SECRET_ID_MALFORMED'
            raise exceptions.ValidationError(msg)
        except Secret.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if not user_has_rights_on_secret(self.context['request'].user.id, secret.id, True, None):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['secret'] = secret

        return attrs