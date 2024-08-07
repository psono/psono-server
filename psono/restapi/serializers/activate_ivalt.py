from rest_framework import serializers, exceptions
from django.conf import settings
from ..utils import decrypt_with_db_secret, ivalt_auth_request_verify
from ..models import Ivalt

class ActivateIvaltSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:

        try:
            ivalt = Ivalt.objects.get(user=self.context['request'].user, active=False)
        except Ivalt.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if not settings.IVALT_SECRET_KEY:
            msg = 'IVALT_SECRET_KEY_NOT_EXIST'
            raise exceptions.ValidationError(msg)
        
        if settings.ALLOWED_SECOND_FACTORS and 'ivalt' not in settings.ALLOWED_SECOND_FACTORS:
            msg = 'SERVER_NOT_SUPPORT_IVALT'
            raise exceptions.ValidationError(msg)
        
        is_success, error_msg = ivalt_auth_request_verify(decrypt_with_db_secret(ivalt.mobile))
        if not is_success:
                msg = error_msg if error_msg else 'AUTHENTICATION_FAILED'
                raise exceptions.ValidationError(msg)
        
        attrs['ivalt'] = ivalt
        return attrs