from rest_framework import serializers, exceptions
from ..fields import UUIDField

from ..utils import user_has_rights_on_secret
from ..models import Secret

class UpdateSecretSerializer(serializers.Serializer):

    secret_id = UUIDField(required=True)
    data = serializers.CharField(required=False)
    data_nonce = serializers.CharField(required=False, max_length=64)
    callback_url = serializers.CharField(required=False, max_length=2048, allow_blank=True)
    callback_user = serializers.CharField(required=False, max_length=128, allow_blank=True)
    callback_pass = serializers.CharField(required=False, max_length=128, allow_blank=True)

    def validate(self, attrs: dict) -> dict:

        secret_id = attrs.get('secret_id')

        try:
            secret = Secret.objects.get(pk=secret_id)
        except Secret.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if not user_has_rights_on_secret(self.context['request'].user.id, secret.id, None, True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['secret'] = secret
        attrs['data'] = attrs.get('data', False)
        attrs['data_nonce'] = attrs.get('data_nonce', False)

        return attrs