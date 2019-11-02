from django.conf import settings
from django.utils.translation import ugettext_lazy as _

from ..utils import authenticate
from rest_framework import serializers, exceptions


class UserDeleteSerializer(serializers.Serializer):

    authkey = serializers.CharField(style={'input_type': 'password'}, required=True,
                                    max_length=settings.AUTH_KEY_LENGTH_BYTES*2,
                                    min_length=settings.AUTH_KEY_LENGTH_BYTES*2)

    def validate(self, attrs: dict) -> dict:

        authkey = attrs.get('authkey', '')

        user, error_code = authenticate(username=self.context['request'].user.username, authkey=authkey)

        if not user:
            msg = _("PASSWORD_INCORRECT")
            raise exceptions.ValidationError(msg)

        return attrs