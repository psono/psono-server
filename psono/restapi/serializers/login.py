from django.conf import settings
from ..utils import authenticate

import dateutil.parser
import nacl.encoding
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

import json
try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions


class LoginSerializer(serializers.Serializer):

    public_key = serializers.CharField(required=True, min_length=64, max_length=64)
    login_info = serializers.CharField(required=False)
    login_info_nonce = serializers.CharField(required=False)
    session_duration = serializers.IntegerField(required=False)

    def validate(self, attrs):

        login_info = attrs.get('login_info', False)
        login_info_nonce = attrs.get('login_info_nonce', False)
        public_key = attrs.get('public_key')
        session_duration = attrs.get('session_duration', settings.DEFAULT_TOKEN_TIME_VALID)

        crypto_box = Box(PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
                         PublicKey(public_key, encoder=nacl.encoding.HexEncoder))

        request_data = json.loads(crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(login_info),
            nacl.encoding.HexEncoder.decode(login_info_nonce)
        ).decode())
        # try:
        # except:
        #     msg = _('Login info cannot be decrypted')
        #     raise exceptions.ValidationError(msg)

        if not request_data.get('username', False):
            msg = _('No username specified.')
            raise exceptions.ValidationError(msg)

        if not request_data.get('authkey', False):
            msg = _('No authkey specified.')
            raise exceptions.ValidationError(msg)

        username = request_data.get('username').lower().strip()
        authkey = request_data.get('authkey')

        user = authenticate(username=username, authkey=authkey)

        if not user:
            msg = _('Username or password wrong.')
            raise exceptions.ValidationError(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.ValidationError(msg)

        if not user.is_email_active:
            msg = _('E-mail is not yet verified.')
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        attrs['user_session_public_key'] = public_key
        attrs['session_duration'] = session_duration

        attrs['device_fingerprint'] = request_data.get('device_fingerprint', '')
        attrs['device_description'] = request_data.get('device_description', '')

        device_time = request_data.get('device_time', None)
        if device_time is None:
            attrs['device_time'] = None
        else:
            attrs['device_time'] = dateutil.parser.parse(device_time)

        return attrs
