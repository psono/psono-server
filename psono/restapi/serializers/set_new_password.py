from django.conf import settings
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.hashers import check_password

from rest_framework import serializers, exceptions

from ..models import User, Recovery_Code

import re

import nacl, datetime
import nacl.encoding


class SetNewPasswordSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'Enter a valid username' })
    recovery_authkey = serializers.CharField(required=True)
    update_data = serializers.CharField(required=True)
    update_data_nonce = serializers.CharField(max_length=64, required=True)



    def validate_update_data(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Update data must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value


    def validate_update_data_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Update data nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate(self, attrs: dict) -> dict:

        username = attrs.get('username')
        recovery_authkey = attrs.get('recovery_authkey')

        update_data = nacl.encoding.HexEncoder.decode(attrs.get('update_data'))
        update_data_nonce = nacl.encoding.HexEncoder.decode(attrs.get('update_data_nonce'))

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


        if recovery_code.verifier_issue_date + datetime.timedelta(0,settings.RECOVERY_VERIFIER_TIME_VALID) < timezone.now():
            msg = _("Validator expired.")
            raise exceptions.ValidationError(msg)

        attrs['update_data'] = update_data
        attrs['update_data_nonce'] = update_data_nonce
        attrs['recovery_code'] = recovery_code
        attrs['user'] = user

        return attrs