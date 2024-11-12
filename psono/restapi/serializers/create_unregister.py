from rest_framework import serializers, exceptions
from django.conf import settings
import bcrypt

from ..models import User


class CreateUnregisterSerializer(serializers.Serializer):
    username = serializers.EmailField(required=False, error_messages={ 'invalid': 'INVALID_USERNAME_FORMAT' })
    email = serializers.EmailField(required=False, error_messages={ 'invalid': 'INVALID_EMAIL_FORMAT' })

    def validate(self, attrs: dict) -> dict:

        username = attrs.get('username', '').lower().strip()
        email = attrs.get('email', '').lower().strip()

        if not username and not email:
            msg = "EITHER_USERNAME_OR_EMAIL_NEED_TO_BE_DEFINED"
            raise exceptions.ValidationError(msg)

        if username and email:
            msg = "EITHER_USERNAME_OR_EMAIL_NEED_TO_BE_DEFINED_NOT_BOTH"
            raise exceptions.ValidationError(msg)

        if username:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                msg = 'USER_WITH_USERNAME_DOESNT_EXIST'
                raise exceptions.ValidationError(msg)
        else:
            email_bcrypt_full = bcrypt.hashpw(email.encode(), settings.EMAIL_SECRET_SALT.encode())
            email_bcrypt = email_bcrypt_full.decode().replace(settings.EMAIL_SECRET_SALT, '', 1)

            try:
                user = User.objects.get(email_bcrypt=email_bcrypt)
            except User.DoesNotExist:
                msg = 'USER_WITH_EMAIL_DOESNT_EXIST'
                raise exceptions.ValidationError(msg)

        attrs['user'] = user

        return attrs


        
