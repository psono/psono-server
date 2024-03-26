from rest_framework import serializers, exceptions

from ..models import Yubikey_OTP
from ..utils import yubikey_authenticate, yubikey_get_yubikey_id, decrypt_with_db_secret

class YubikeyOTPVerifySerializer(serializers.Serializer):
    yubikey_otp = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        yubikey_otp = attrs.get('yubikey_otp', '').strip()

        yubikey_is_valid = yubikey_authenticate(yubikey_otp)

        if yubikey_is_valid is None:
            msg = 'SERVER_NOT_SUPPORT_YUBIKEY'
            raise exceptions.ValidationError(msg)

        if not yubikey_is_valid:
            msg = 'YUBICO_TOKEN_INVALID'
            raise exceptions.ValidationError(msg)

        token = self.context['request'].auth

        yubikey_id = yubikey_get_yubikey_id(yubikey_otp)

        yks = Yubikey_OTP.objects.filter(user_id=token.user_id).all()
        if len(yks) < 1:
            msg = 'NO_YUBIKEY_FOUND'
            raise exceptions.ValidationError(msg)

        otp_token_correct = False
        for yk in yks:
            decrypted_yubikey_id = decrypt_with_db_secret(yk.yubikey_id).encode()

            if yubikey_id.encode() == decrypted_yubikey_id:
                otp_token_correct = True
                attrs['yubikey_otp'] = yk
                break

        if not otp_token_correct:
            # TODO replace with YUBICO_TOKEN_VALID_BUT_NOT_CONFIGURED
            msg = 'YubiKey OTP not attached to this account.'
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs