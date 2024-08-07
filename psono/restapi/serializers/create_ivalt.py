from rest_framework import serializers, exceptions
from django.conf import settings
from ..models import Ivalt
from ..utils import ivalt_auth_request_sent


class CreateIvaltSerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length=256, required=True)

    def validate(self, attrs: dict) -> dict:

        mobile = attrs.get('mobile', '').strip()

        if not settings.IVALT_SECRET_KEY or settings.IVALT_SECRET_KEY == '':  #nosec -- not [B105:hardcoded_password_string]
            msg = 'IVALT_SECRET_KEY_NOT_EXIST'
            raise exceptions.ValidationError(msg)
        
        if settings.ALLOWED_SECOND_FACTORS and 'ivalt' not in settings.ALLOWED_SECOND_FACTORS:
            msg = 'SERVER_NOT_SUPPORT_IVALT'
            raise exceptions.ValidationError(msg)

        if Ivalt.objects.filter(user=self.context['request'].user).exists():
            msg = 'ONLY_ONE_IVALT_MOBILE_ALLOWED'
            raise exceptions.ValidationError(msg)
        
        is_success = ivalt_auth_request_sent(mobile)
        
        if not is_success:
            msg = 'AUTHENTICATION_FAILED'
            raise exceptions.ValidationError(msg)
        
        attrs['mobile'] = mobile
        return attrs


        
