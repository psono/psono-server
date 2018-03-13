from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import Yubikey_OTP

class DeleteYubikeySerializer(serializers.Serializer):

    yubikey_otp_id = serializers.UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        yubikey_otp_id = attrs.get('yubikey_otp_id')

        try:
            yubikey_otp = Yubikey_OTP.objects.get(pk=yubikey_otp_id, user=self.context['request'].user)
        except Yubikey_OTP.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        yubikey_otp_count = Yubikey_OTP.objects.filter(user=self.context['request'].user).count()



        attrs['yubikey_otp'] = yubikey_otp
        attrs['yubikey_otp_count'] = yubikey_otp_count

        return attrs