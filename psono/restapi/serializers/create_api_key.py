import re

from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, exceptions

from ..fields import BooleanField

class CreateAPIKeySerializer(serializers.Serializer):

    title = serializers.CharField(max_length=256, required=True)
    read = BooleanField(required=False, default=True)
    write = BooleanField(required=False, default=False)
    restrict_to_secrets = BooleanField(required=False, default=False)
    allow_insecure_access = BooleanField(required=False, default=False)
    public_key = serializers.CharField(required=True)
    private_key = serializers.CharField(required=True)
    private_key_nonce = serializers.CharField(max_length=64, required=True)
    secret_key = serializers.CharField(required=True)
    secret_key_nonce = serializers.CharField(max_length=64, required=True)
    user_private_key = serializers.CharField(required=True)
    user_private_key_nonce = serializers.CharField(max_length=64, required=True)
    user_secret_key = serializers.CharField(required=True)
    user_secret_key_nonce = serializers.CharField(max_length=64, required=True)
    verify_key = serializers.CharField(max_length=64, required=True)

    def validate_public_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Public key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Private key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Private key nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

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

    def validate_user_private_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('User private key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_user_private_key_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('User private key nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_user_secret_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('User secret key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_user_secret_key_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('User secret key nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_verify_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Verify key nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value