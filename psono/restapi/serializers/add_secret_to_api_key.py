import re

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions

from ..fields import UUIDField
from ..models import API_Key, Secret
from ..utils import user_has_rights_on_secret

class AddSecretToAPIKeySerializer(serializers.Serializer):

    api_key_id = UUIDField(required=True)
    secret_id = UUIDField(required=True)
    secret_key = serializers.CharField(required=True)
    secret_key_nonce = serializers.CharField(max_length=64, required=True)
    title = serializers.CharField(required=True)
    title_nonce = serializers.CharField(max_length=64, required=True)

    def validate_secret_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Secret key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Secret key nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_title(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Secret key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_title_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Secret key nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate(self, attrs: dict) -> dict:

        api_key_id = attrs.get('api_key_id')
        secret_id = attrs.get('secret_id')


        try:
            api_key = API_Key.objects.get(pk=api_key_id, user=self.context['request'].user)
        except API_Key.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        try:
            secret = Secret.objects.get(pk=secret_id)
        except Secret.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)


        if not user_has_rights_on_secret(self.context['request'].user.id, secret.id):
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)


        attrs['api_key'] = api_key
        attrs['secret'] = secret

        return attrs