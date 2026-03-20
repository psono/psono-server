from django.conf import settings
from ..utils import yubikey_authenticate

from rest_framework import serializers, exceptions


class NewYubikeyOTPSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)
    yubikey_otp = serializers.CharField(max_length=64)

    def validate_yubikey_otp(self, value):

        value = value.strip()

        if (
            settings.ALLOWED_SECOND_FACTORS
            and "yubikey_otp" not in settings.ALLOWED_SECOND_FACTORS
        ):
            msg = "SERVER_NOT_SUPPORT_YUBIKEY"
            raise exceptions.ValidationError(msg)

        yubikey_is_valid = yubikey_authenticate(value)

        if yubikey_is_valid is None:
            msg = "SERVER_NOT_SUPPORT_YUBIKEY"
            raise exceptions.ValidationError(msg)

        if not yubikey_is_valid:
            msg = "YUBICO_TOKEN_INVALID"
            raise exceptions.ValidationError(msg)

        return value
