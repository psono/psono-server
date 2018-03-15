from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions
from ..fields import UUIDField

import bcrypt

from ..models import User


class UserSearchSerializer(serializers.Serializer):

    user_id = UUIDField(required=False)
    user_username = serializers.CharField(required=False)
    user_email = serializers.CharField(required=False)

    def validate(self, attrs: dict) -> dict:

        user_id = attrs.get('user_id', '')
        user_username = attrs.get('user_username', '').lower().strip()
        user_email = attrs.get('user_email', '').lower().strip()

        users = []

        if user_id:
            try:
                users.append(User.objects.get(pk=str(user_id)))
            except User.DoesNotExist:
                pass

        if user_username and not settings.ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL:
            try:
                users.append(User.objects.get(username=str(user_username)))
            except User.DoesNotExist:
                pass
        elif user_username and settings.ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL:
            user_split = user_username.split('@', 1)
            for user in User.objects.filter(username__contains=str(user_split[0])).all():
                users.append(user)


        if settings.ALLOW_USER_SEARCH_BY_EMAIL and user_email:
            email_bcrypt_full = bcrypt.hashpw(user_email.encode(), settings.EMAIL_SECRET_SALT.encode())
            email_bcrypt = email_bcrypt_full.decode().replace(settings.EMAIL_SECRET_SALT, '', 1)
            for user in User.objects.filter(email=email_bcrypt).all():
                users.append(user)

        if not user_id and not user_username and settings.ALLOW_USER_SEARCH_BY_EMAIL and not user_email:
            msg = _("Either user id or username or user email need to be specified.")
            raise exceptions.ValidationError(msg)


        if not user_id and not user_username and not settings.ALLOW_USER_SEARCH_BY_EMAIL:
            msg = _("Either user id or username need to be specified.")
            raise exceptions.ValidationError(msg)


        if len(users) == 0:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['users'] = users

        return attrs
