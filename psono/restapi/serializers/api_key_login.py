from django.conf import settings
from ..utils import authenticate

import dateutil.parser
import nacl.encoding
import nacl.utils
import nacl.signing
from  nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey, PublicKey, Box

import json
import binascii

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions

from ..models import API_Key

class APIKeyLoginSerializer(serializers.Serializer):

    info = serializers.CharField(required=True)
    signature = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        info_json = attrs.get('info')
        signature = attrs.get('signature')

        try:
            info = json.loads(info_json)
        except:
            msg = _('Login info no valid json')
            raise exceptions.ValidationError(msg)

        api_key_id = info['api_key_id']
        session_public_key = info['session_public_key']
        session_duration = info.get('session_duration', settings.DEFAULT_TOKEN_TIME_VALID)
        device_description = info.get('device_description', '')
        device_fingerprint = info.get('device_fingerprint', '')
        device_time = info.get('device_time', None)

        # check Permissions on group
        try:
            api_key = API_Key.objects.get(id=api_key_id, active=True)
        except API_Key.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        if not api_key.user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.ValidationError(msg)

        if not api_key.user.is_email_active:
            msg = _('E-mail is not yet verified.')
            raise exceptions.ValidationError(msg)


        verify_key = nacl.signing.VerifyKey(api_key.verify_key, encoder=nacl.encoding.HexEncoder)

        try:
            verify_key.verify(info_json.encode(), binascii.unhexlify(signature.encode()))
        except BadSignatureError:
            msg = _('Signature invalid.')
            raise exceptions.ValidationError(msg)

        attrs['api_key'] = api_key
        attrs['user_session_public_key'] = session_public_key
        attrs['session_duration'] = session_duration
        attrs['device_description'] = device_description
        attrs['device_fingerprint'] = device_fingerprint

        if device_time is None:
            attrs['device_time'] = None
        else:
            attrs['device_time'] = dateutil.parser.parse(device_time)

        return attrs
