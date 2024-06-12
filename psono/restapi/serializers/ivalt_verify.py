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
            ivalt = Ivalt.objects.get(user=self.context['request'].user, active=True).only('mobile')
        except Ivalt.DoesNotExist:
            msg = "NO_IVALT_2FA_FOUND"
            raise exceptions.ValidationError(msg)

        if request_type == 'notification':
            response = ivalt_auth_request_sent(decrypt_with_db_secret(ivalt.mobile))
        else:
            response = ivalt_auth_request_verify(decrypt_with_db_secret(ivalt.mobile))
        data = response.get("data")
        error = response.get("error")
        if data and data["status"]:
            attrs['request_type'] = request_type
            attrs['token'] = token
            return attrs
        else:
            raise exceptions.ValidationError(error)
