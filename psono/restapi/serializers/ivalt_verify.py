from rest_framework import serializers, exceptions
from ..models import Ivalt, Token
from ..utils import decrypt_with_db_secret, ivalt_auth_request_sent, ivalt_auth_request_verify


class IvaltVerifySerializer(serializers.Serializer):
    request_type = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        request_type = attrs.get('request_type', '').lower().strip()

        if request_type not in ['notification', 'verification']:
            msg = 'INAVLID_VALUE_FOR_REQUEST_TYPE'
            raise exceptions.ValidationError(msg)

        token = self.context['request'].auth

        try:
            ivalt = Ivalt.objects.get(user=self.context['request'].user, active=True)
        except Ivalt.DoesNotExist:
            msg = "NO_IVALT_2FA_FOUND"
            raise exceptions.ValidationError(msg)

        if request_type == 'notification':
            is_success = ivalt_auth_request_sent(decrypt_with_db_secret(ivalt.mobile))
            if not is_success:
                msg = 'AUTHENTICATION_FAILED'
                raise exceptions.ValidationError(msg)
        else:
            is_success, error_msg = ivalt_auth_request_verify(decrypt_with_db_secret(ivalt.mobile))
            if not is_success:
                msg = error_msg if error_msg else 'AUTHENTICATION_FAILED'
                raise exceptions.ValidationError(msg)
 
        attrs['request_type'] = request_type
        attrs['token'] = token
        return attrs
