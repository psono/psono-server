from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions

from restapi.models import Yubikey_OTP

class DeleteYubikeySerializer(serializers.Serializer):
    yubikey_id = serializers.UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        yubikey_otp_id = attrs.get('yubikey_otp_id')

        try:
            yubikey_otp = Yubikey_OTP.objects.get(pk=yubikey_otp_id)
        except Yubikey_OTP.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['yubikey_otp'] = yubikey_otp

        return attrs
