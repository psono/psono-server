from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions

from ..utils import user_has_rights_on_secret
from ..models import Secret

class UpdateSecretSerializer(serializers.Serializer):

    secret_id = serializers.UUIDField(required=True)
    data = serializers.CharField(required=False)
    data_nonce = serializers.CharField(required=False, max_length=64)

    def validate(self, attrs: dict) -> dict:

        secret_id = attrs.get('secret_id')

        try:
            secret = Secret.objects.get(pk=secret_id)
        except Secret.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        if not user_has_rights_on_secret(self.context['request'].user.id, secret.id, None, True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['secret'] = secret
        attrs['data'] = attrs.get('data', False)
        attrs['data_nonce'] = attrs.get('data_nonce', False)

        return attrs