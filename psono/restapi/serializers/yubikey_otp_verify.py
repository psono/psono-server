from django.conf import settings
from ..utils import yubikey_authenticate, yubikey_get_yubikey_id
import hashlib
import six

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import Yubikey_OTP
import nacl.utils
import nacl.secret
import nacl.encoding

class YubikeyOTPVerifySerializer(serializers.Serializer):
    yubikey_otp = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        yubikey_otp = attrs.get('yubikey_otp').strip()

        yubikey_is_valid = yubikey_authenticate(yubikey_otp)

        if yubikey_is_valid is None:
            msg = _('Server does not support YubiKeys.')
            raise exceptions.ValidationError(msg)

        if not yubikey_is_valid:
            msg = _('YubiKey OTP incorrect.')
            raise exceptions.ValidationError(msg)

        token = self.context['request'].auth

        if token.active:
            msg = _('Token incorrect.')
            raise exceptions.ValidationError(msg)

        # prepare decryption
        secret_key = hashlib.sha256(settings.DB_SECRET.encode('utf-8')).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)

        yubikey_id = yubikey_get_yubikey_id(yubikey_otp)

        otp_token_correct = False
        for yk in Yubikey_OTP.objects.filter(user_id=token.user_id):
            encrypted_yubikey_id = nacl.encoding.HexEncoder.decode(yk.yubikey_id)
            decrypted_yubikey_id = crypto_box.decrypt(encrypted_yubikey_id)

            if six.b(yubikey_id) == decrypted_yubikey_id:
                otp_token_correct = True
                attrs['yubikey_otp'] = yk
                break

        if not otp_token_correct:
            msg = _('YubiKey OTP not attached to this account.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs