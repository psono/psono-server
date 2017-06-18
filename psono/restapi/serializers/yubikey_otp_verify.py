from django.conf import settings
from ..utils import yubikey_authenticate, yubikey_get_yubikey_id
from ..authentication import TokenAuthentication
import hashlib
import six

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import Token, Yubikey_OTP
import nacl.utils
import nacl.secret
import nacl.encoding

class YubikeyOTPVerifySerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    yubikey_otp = serializers.CharField(required=True)

    def validate(self, attrs):

        yubikey_otp = attrs.get('yubikey_otp').strip()

        yubikey_is_valid = yubikey_authenticate(yubikey_otp)

        if yubikey_is_valid is None:
            msg = _('Server does not support YubiKeys.')
            raise exceptions.ValidationError(msg)

        if not yubikey_is_valid:
            msg = _('YubiKey OTP incorrect.')
            raise exceptions.ValidationError(msg)

        token_hash = TokenAuthentication.user_token_to_token_hash(attrs.get('token'))

        try:
            token = Token.objects.filter(key=token_hash, active=False).get()
        except Token.DoesNotExist:
            msg = _('Token incorrect.')
            raise exceptions.ValidationError(msg)

        # prepare decryption
        secret_key = hashlib.sha256(settings.DB_SECRET.encode('utf-8')).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)

        yubikey_id = yubikey_get_yubikey_id(yubikey_otp)

        otp_token_correct = False
        for yk in Yubikey_OTP.objects.filter(user=token.user):
            encrypted_yubikey_id = nacl.encoding.HexEncoder.decode(yk.yubikey_id)
            decrypted_yubikey_id = crypto_box.decrypt(encrypted_yubikey_id)

            if six.b(yubikey_id) == decrypted_yubikey_id:
                otp_token_correct = True
                break

        if not otp_token_correct:
            msg = _('YubiKey OTP not attached to this account.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs