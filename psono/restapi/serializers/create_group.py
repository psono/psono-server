import re

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions


class CreateGroupSerializer(serializers.Serializer):

    name = serializers.CharField(required=True)
    secret_key = serializers.CharField(required=True)
    secret_key_nonce = serializers.CharField(max_length=64, required=True)
    private_key = serializers.CharField(required=True)
    private_key_nonce = serializers.CharField(max_length=64, required=True)
    public_key = serializers.CharField(required=True)

    def validate_secret_key(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('secret_key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key_nonce(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('secret_key_nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('private_key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key_nonce(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('private_key_nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_public_key(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('public_key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value