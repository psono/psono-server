from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions
from ..fields import UUIDField
import six

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
            msg = _('Server does not support YubiKeys.')
            raise exceptions.ValidationError(msg)

        if not yubikey_is_valid:
            msg = _('YubiKey OTP incorrect.')
            raise exceptions.ValidationError(msg)

        yubikey_token_id = yubikey_get_yubikey_id(yubikey_otp)

        try:
            yubikey_otp = Yubikey_OTP.objects.get(pk=yubikey_id, user=self.context['request'].user)
        except Yubikey_OTP.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        decrypted_yubikey_id = decrypt_with_db_secret(yubikey_otp.yubikey_id).encode()

        if six.b(yubikey_token_id) != decrypted_yubikey_id:
            msg = _('YubiKey OTP not attached to this account.')
            raise exceptions.ValidationError(msg)

        attrs['yubikey_otp'] = yubikey_otp
        return attrs