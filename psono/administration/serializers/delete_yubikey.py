from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Yubikey_OTP

class DeleteYubikeySerializer(serializers.Serializer):
    yubikey_otp_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        yubikey_otp_id = attrs.get('yubikey_otp_id')

        try:
            yubikey_otp = Yubikey_OTP.objects.get(pk=yubikey_otp_id)
        except Yubikey_OTP.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['yubikey_otp'] = yubikey_otp

        return attrs
