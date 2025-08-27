
from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Yubikey_OTP

class DeleteYubikeySerializer(serializers.Serializer):

    yubikey_otp_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        yubikey_otp_id = attrs.get('yubikey_otp_id')

        try:
            yubikey_otp = Yubikey_OTP.objects.get(pk=yubikey_otp_id, user=self.context['request'].user)
        except Yubikey_OTP.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        yubikey_otp_count = Yubikey_OTP.objects.filter(user=self.context['request'].user, active=True).count()



        attrs['yubikey_otp'] = yubikey_otp
        attrs['yubikey_otp_count'] = yubikey_otp_count

        return attrs