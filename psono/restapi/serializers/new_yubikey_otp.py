from django.conf import settings
from yubico_client import Yubico

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions


class NewYubikeyOTPSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)
    yubikey_otp = serializers.CharField(max_length=64)


    def validate_yubikey_otp(self, value):

        value = value.strip()

        if settings.YUBIKEY_CLIENT_ID is None or settings.YUBIKEY_SECRET_KEY is None:
            msg = _('Server does not support Yubikeys')
            raise exceptions.ValidationError(msg)

        client = Yubico(settings.YUBIKEY_CLIENT_ID, settings.YUBIKEY_SECRET_KEY)
        try:
            yubikey_is_valid = client.verify(value)
        except:
            yubikey_is_valid = False

        if not yubikey_is_valid:
            msg = _('Yubikey token invalid')
            raise exceptions.ValidationError(msg)

        return value