from django.conf import settings
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.hashers import check_password

from rest_framework import serializers, exceptions

from ..models import User, Emergency_Code

import re
import json
import dateutil.parser
import nacl, datetime
import nacl.encoding
from nacl.public import PrivateKey, PublicKey, Box


class ActivateEmergencyLoginSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'INVALID_USERNAME_FORMAT' })
    emergency_authkey = serializers.CharField(required=True)
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
        emergency_authkey = attrs.get('emergency_authkey')

        update_data = nacl.encoding.HexEncoder.decode(attrs.get('update_data'))
        update_data_nonce = nacl.encoding.HexEncoder.decode(attrs.get('update_data_nonce'))

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            msg = "USERNAME_OR_RECOVERY_CODE_INCORRECT"
            raise exceptions.ValidationError(msg)


        emergency_codes = Emergency_Code.objects.filter(user_id=user.id)

        valid_emergency_code = None

        for emergency_code in emergency_codes:
            if not check_password(emergency_authkey, emergency_code.emergency_authkey):
                continue
            valid_emergency_code = emergency_code
            break

        if not valid_emergency_code:
            msg = _("Username or emergency code incorrect.")
            raise exceptions.ValidationError(msg)


        if valid_emergency_code.verifier_issue_date + datetime.timedelta(0,settings.RECOVERY_VERIFIER_TIME_VALID) < timezone.now():
            msg = _("Validator expired.")
            raise exceptions.ValidationError(msg)

        try:
            crypto_box = Box(PrivateKey(valid_emergency_code.verifier, encoder=nacl.encoding.HexEncoder),
                             PublicKey(user.public_key, encoder=nacl.encoding.HexEncoder))

            login_info = json.loads(crypto_box.decrypt(update_data, update_data_nonce).decode())

        except:
            msg = _("Validator failed.")
            raise exceptions.ValidationError(msg)


        if not valid_emergency_code.user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.ValidationError(msg)

        if not valid_emergency_code.user.is_email_active:
            msg = _('E-mail is not yet verified.')
            raise exceptions.ValidationError(msg)

        attrs['emergency_code'] = valid_emergency_code
        attrs['user'] = user
        attrs['session_duration'] = settings.DEFAULT_TOKEN_TIME_VALID

        attrs['device_fingerprint'] = login_info.get('device_fingerprint', '')
        attrs['device_description'] = login_info.get('device_description', '')
        attrs['user_session_public_key'] = login_info.get('session_public_key', '')

        device_time = login_info.get('device_time', None)
        if device_time is None:
            attrs['device_time'] = None
        else:
            attrs['device_time'] = dateutil.parser.parse(device_time)

        return attrs