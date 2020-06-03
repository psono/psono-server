from django.conf import settings
from rest_framework import serializers
import bcrypt

from restapi.models import User

class CreateUserSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True, error_messages={'invalid': 'INVALID_USERNAME_FORMAT'})
    email = serializers.EmailField(required=True, error_messages={'invalid': 'INVALID_EMAIL_FORMAT'})
    password = serializers.CharField(required=False)


    def validate(self, attrs: dict) -> dict:

        email = attrs.get('email', '')
        username = attrs.get('username', '')
        password = attrs.get('password', '')

        username = username.strip().lower()
        email = email.strip().lower()

        email_bcrypt = bcrypt.hashpw(email.encode(), settings.EMAIL_SECRET_SALT.encode()).decode().replace(
            settings.EMAIL_SECRET_SALT, '', 1)

        if User.objects.filter(email_bcrypt=email_bcrypt).exists():
            return {'error': 'USER_WITH_EMAIL_ALREADY_EXISTS'}

        if User.objects.filter(username=username).exists():
            return {'error': 'USER_WITH_USERNAME_ALREADY_EXISTS'}

        attrs['user'] = username
        attrs['email'] = email
        attrs['password'] = password

        return attrs
