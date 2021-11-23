from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions

import re
import bcrypt

from ..utils import authenticate
from ..models import User, Old_Credential


class UserUpdateSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_null=True, error_messages={ 'invalid': 'INVALID_EMAIL_FORMAT' })
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

    def validate(self, attrs: dict) -> dict:
        email = attrs.get('email')
        authkey_old = attrs.get('authkey_old')
        authkey = attrs.get('authkey', False)

        if email:
            email = email.lower().strip()
            email_bcrypt = bcrypt.hashpw(email.encode(), settings.EMAIL_SECRET_SALT.encode()).decode().replace(
                settings.EMAIL_SECRET_SALT, '', 1)
            if User.objects.filter(email_bcrypt=email_bcrypt).exclude(pk=self.context['request'].user.pk).exists():
                msg = _('E-Mail already exists.')
                raise exceptions.ValidationError(msg)
            attrs['email'] = email

        user, error_code = authenticate(username=self.context['request'].user.username, authkey=str(authkey_old))

        if not user:
            msg = _("OLD_PASSWORD_INCORRECT")
            raise exceptions.ValidationError(msg)

        if authkey and settings.DISABLE_LAST_PASSWORDS > 0:
            user, error_code = authenticate(username=self.context['request'].user.username, authkey=str(authkey))
            if user:
                msg = _("You cannot use your old passwords again.")
                raise exceptions.ValidationError(msg)

            if settings.DISABLE_LAST_PASSWORDS > 1:
                old_credentials = Old_Credential.objects.filter(user=self.context['request'].user).order_by('-create_date')[:settings.DISABLE_LAST_PASSWORDS-1]

                for old_cred in old_credentials:
                    if check_password(authkey, old_cred.authkey):
                        msg = _("You cannot use your old passwords again.")
                        raise exceptions.ValidationError(msg)

        return attrs

    def validate_private_key(self, value):

        if value is not None:
            value = value.strip()

            if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
                msg = _('private_key must be in hex representation')
                raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key_nonce(self, value):

        if value is not None:
            value = value.strip()

            if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
                msg = _('secret_key_nonce must be in hex representation')
                raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key(self, value):

        if value is not None:
            value = value.strip()

            if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
                msg = _('secret_key must be in hex representation')
                raise exceptions.ValidationError(msg)

        return value

    def validate_private_key_nonce(self, value):

        if value is not None:
            value = value.strip()

            if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
                msg = _('private_key_nonce must be in hex representation')
                raise exceptions.ValidationError(msg)

        return value