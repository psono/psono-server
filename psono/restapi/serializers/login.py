from django.conf import settings
from ..utils import authenticate

import dateutil.parser
import nacl.encoding
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

import json

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions


class LoginSerializer(serializers.Serializer):

    public_key = serializers.CharField(required=True, min_length=64, max_length=64)
    login_info = serializers.CharField(required=True)
    login_info_nonce = serializers.CharField(required=True)
    session_duration = serializers.IntegerField(required=False)

    def validate(self, attrs: dict) -> dict:

        login_info = attrs.get('login_info')
        login_info_nonce = attrs.get('login_info_nonce')
        public_key = attrs.get('public_key')
        session_duration = attrs.get('session_duration', settings.DEFAULT_TOKEN_TIME_VALID)

        crypto_box = Box(PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
                         PublicKey(public_key, encoder=nacl.encoding.HexEncoder))

        try:
            request_data = json.loads(crypto_box.decrypt(
                nacl.encoding.HexEncoder.decode(login_info),
                nacl.encoding.HexEncoder.decode(login_info_nonce)
            ).decode())
        except:
            msg = 'LOGIN_INFO_CANNOT_BE_DECRYPTED'
            raise exceptions.ValidationError(msg)

        if not request_data.get('username', False):
            # TODO Replace with USERNAME_REQUIRED
            msg = _('No username specified.')
            raise exceptions.ValidationError(msg)

        if not request_data.get('authkey', False):
            # TODO Replace with AUTHKEY_REQUIRED
            msg = _('No authkey specified.')
            raise exceptions.ValidationError(msg)

        username = request_data.get('username').lower().strip()
        authkey = request_data.get('authkey')
        password = request_data.get('password', False)
        source = request_data.get('client_type', 'webclient')

        if source == 'app':
            session_duration = min(session_duration, settings.MAX_APP_TOKEN_TIME_VALID)
        else:
            # e.g. webclient
            session_duration = min(session_duration, settings.MAX_WEBCLIENT_TOKEN_TIME_VALID)

        user, error_code = authenticate(username=username, authkey=authkey, password=password)

        if not user:
            msg = 'USERNAME_OR_PASSWORD_WRONG'
            raise exceptions.ValidationError(msg)

        if not user.is_active:
            msg = 'USER_DISABLED_ASK_ADMIN_TO_ENABLE'
            raise exceptions.ValidationError(msg)

        if not user.is_email_active:
            msg = 'ACCOUNT_NOT_VERIFIED'
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
