from rest_framework import serializers, exceptions
from ..fields import UUIDField

from ..models import Yubikey_OTP
from ..utils import yubikey_authenticate, yubikey_get_yubikey_id, decrypt_with_db_secret

class ActivateYubikeySerializer(serializers.Serializer):
    yubikey_id = UUIDField(required=True)
    yubikey_otp = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        yubikey_id = attrs.get('yubikey_id', '')
        yubikey_otp = attrs.get('yubikey_otp', '').strip()

        yubikey_is_valid = yubikey_authenticate(yubikey_otp)

        if yubikey_is_valid is None:
            msg = 'SERVER_DOES_NOT_SUPPORT_YUBIKEYS'
            raise exceptions.ValidationError(msg)

        if not yubikey_is_valid:
            msg = 'YUBIKEY_OTP_INCORRECT'
            raise exceptions.ValidationError(msg)

        yubikey_token_id = yubikey_get_yubikey_id(yubikey_otp)

        try:
            yubikey_otp = Yubikey_OTP.objects.get(pk=yubikey_id, user=self.context['request'].user)
        except Yubikey_OTP.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        decrypted_yubikey_id = decrypt_with_db_secret(yubikey_otp.yubikey_id).encode()

        if yubikey_token_id.encode() != decrypted_yubikey_id:
            msg = 'YUBIKEY_OTP_NOT_ATTACHED_TO_THIS_ACCOUNT'
            raise exceptions.ValidationError(msg)

        attrs['yubikey_otp'] = yubikey_otp
        return attrs