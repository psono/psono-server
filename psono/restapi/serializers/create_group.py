import re

from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import gettext_lazy as _

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

    def validate_name(self, value):
        value = value.strip()

        if len(value) < 3:
            msg = _('Name may not be shorter than 3 chars.')
            raise exceptions.ValidationError(msg)

        if '@' in value:
            msg = _('Name may not contain an "@"')
            raise exceptions.ValidationError(msg)

        return value