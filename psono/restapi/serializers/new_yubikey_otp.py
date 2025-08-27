from django.conf import settings
from yubico_client import Yubico


from rest_framework import serializers, exceptions


class NewYubikeyOTPSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)
    yubikey_otp = serializers.CharField(max_length=64)


    def validate_yubikey_otp(self, value):

        value = value.strip()

        if settings.ALLOWED_SECOND_FACTORS and 'yubikey_otp' not in settings.ALLOWED_SECOND_FACTORS:
            msg = 'SERVER_NOT_SUPPORT_YUBIKEY'
            raise exceptions.ValidationError(msg)

        if settings.YUBIKEY_CLIENT_ID is None or settings.YUBIKEY_SECRET_KEY is None:
            msg = 'SERVER_NOT_SUPPORT_YUBIKEY'
            raise exceptions.ValidationError(msg)

        client = Yubico(settings.YUBIKEY_CLIENT_ID, settings.YUBIKEY_SECRET_KEY)
        try:
            yubikey_is_valid = client.verify(value)
        except:
            yubikey_is_valid = False

        if not yubikey_is_valid:
            msg = 'YUBICO_TOKEN_INVALID'
            raise exceptions.ValidationError(msg)

        return value