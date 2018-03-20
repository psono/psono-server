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
        user_index = {}
        users = []

        if user_id:
            try:
                user = User.objects.get(pk=str(user_id))
                if user.id not in user_index:
                    users.append(user)
                    user_index[user.id] = True
            except User.DoesNotExist:
                pass

        if user_username and not settings.ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL:
            try:
                user = User.objects.get(username=str(user_username))
                if user.id not in user_index:
                    users.append(user)
                    user_index[user.id] = True
            except User.DoesNotExist:
                pass
        elif user_username and settings.ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL:
            user_split = user_username.split('@', 1)
            for user in User.objects.filter(username__contains=str(user_split[0])).all():
                if user.id not in user_index:
                    users.append(user)
                    user_index[user.id] = True


        if settings.ALLOW_USER_SEARCH_BY_EMAIL and user_email:
            email_bcrypt_full = bcrypt.hashpw(user_email.encode(), settings.EMAIL_SECRET_SALT.encode())
            email_bcrypt = email_bcrypt_full.decode().replace(settings.EMAIL_SECRET_SALT, '', 1)
            for user in User.objects.filter(email_bcrypt=email_bcrypt).all():
                if user.id not in user_index:
                    users.append(user)
                    user_index[user.id] = True

        if len(users) == 0:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['users'] = users

        return attrs
