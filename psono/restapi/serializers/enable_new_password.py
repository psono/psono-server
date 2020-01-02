from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.hashers import check_password
from django.conf import settings

from rest_framework import serializers, exceptions

from ..models import User, Recovery_Code


class EnableNewPasswordSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'INVALID_USERNAME_FORMAT' })
    recovery_authkey = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        username = attrs.get('username')
        recovery_authkey = attrs.get('recovery_authkey')

        if not settings.ALLOW_LOST_PASSWORD:
            msg = _("PASSWORD_RESET_HAS_BEEN_DISABLED")
            raise exceptions.ValidationError(msg)


        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # TODO REPLACE WITH USERNAME_OR_RECOVERY_CODE_INCORRECT
            msg = _("Username or recovery code incorrect.")
            raise exceptions.ValidationError(msg)

        try:
            recovery_code = Recovery_Code.objects.get(user_id=user.id)

            if not check_password(recovery_authkey, recovery_code.recovery_authkey):
            # TODO REPLACE WITH USERNAME_OR_RECOVERY_CODE_INCORRECT
                msg = _("Username or recovery code incorrect.")
                raise exceptions.ValidationError(msg)

        except Recovery_Code.DoesNotExist:
            # TODO REPLACE WITH USERNAME_OR_RECOVERY_CODE_INCORRECT
            msg = _("Username or recovery code incorrect.")
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        attrs['recovery_code'] = recovery_code

        return attrs