import re

from django.utils.http import urlsafe_base64_decode as uid_decoder


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
            msg = 'NO_VALID_HEX'
            raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key_nonce(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = 'NO_VALID_HEX'
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = 'NO_VALID_HEX'
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key_nonce(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = 'NO_VALID_HEX'
            raise exceptions.ValidationError(msg)

        return value

    def validate_public_key(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = 'NO_VALID_HEX'
            raise exceptions.ValidationError(msg)

        return value

    def validate_name(self, value):
        value = value.strip()

        if len(value) < 3:
            msg = 'NAME_MAY_NOT_BE_SHORTER_THAN_3_CHARS'
            raise exceptions.ValidationError(msg)

        if '@' in value:
            msg = 'NAME_MAY_NOT_CONTAIN_AT'
            raise exceptions.ValidationError(msg)

        return value