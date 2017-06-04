from django.conf import settings
import re
import bcrypt

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import User



class UserUpdateSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_null=True)
    authkey = serializers.CharField(style={'input_type': 'password'}, required=False, allow_null=True,
                                    max_length=settings.AUTH_KEY_LENGTH_BYTES*2,
                                    min_length=settings.AUTH_KEY_LENGTH_BYTES*2)
    authkey_old = serializers.CharField(style={'input_type': 'password'}, required=True,
                                    max_length=settings.AUTH_KEY_LENGTH_BYTES*2,
                                    min_length=settings.AUTH_KEY_LENGTH_BYTES*2)

    private_key = serializers.CharField(required=False, allow_null=True,
                                    max_length=settings.USER_PRIVATE_KEY_LENGTH_BYTES*2,
                                    min_length=settings.USER_PRIVATE_KEY_LENGTH_BYTES*2)
    private_key_nonce = serializers.CharField(max_length=64, required=False, allow_null=True)
    secret_key = serializers.CharField(required=False, allow_null=True,
                                    max_length=settings.USER_SECRET_KEY_LENGTH_BYTES*2,
                                    min_length=settings.USER_SECRET_KEY_LENGTH_BYTES*2)
    secret_key_nonce = serializers.CharField(max_length=64, required=False, allow_null=True)

    def validate(self, attrs):
        email = attrs.get('email')

        if email:
            email = email.lower().strip()
            email_bcrypt = bcrypt.hashpw(email.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(
                settings.EMAIL_SECRET_SALT, '', 1)
            if User.objects.filter(email_bcrypt=email_bcrypt).exclude(pk=self.context['request'].user.pk).exists():
                msg = _('E-Mail already exists.')
                raise exceptions.ValidationError(msg)
            attrs['email'] = email

        return attrs

    def validate_private_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('private_key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('secret_key_nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('secret_key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('private_key_nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value