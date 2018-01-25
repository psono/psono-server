from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.hashers import check_password

from rest_framework import serializers, exceptions

from ..models import User, Recovery_Code


class EnableNewPasswordSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'Enter a valid username' })
    recovery_authkey = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        username = attrs.get('username')
        recovery_authkey = attrs.get('recovery_authkey')


        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            msg = _("Username or recovery code incorrect.")
            raise exceptions.ValidationError(msg)

        try:
            recovery_code = Recovery_Code.objects.get(user_id=user.id)

            if not check_password(recovery_authkey, recovery_code.recovery_authkey):
                msg = _("Username or recovery code incorrect.")
                raise exceptions.ValidationError(msg)

        except Recovery_Code.DoesNotExist:
                msg = _("Username or recovery code incorrect.")
                raise exceptions.ValidationError(msg)

        attrs['user'] = user
        attrs['recovery_code'] = recovery_code

        return attrs