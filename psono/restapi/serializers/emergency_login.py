from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.hashers import check_password

from rest_framework import serializers, exceptions

from ..models import User, Emergency_Code


class EmergencyLoginSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'INVALID_USERNAME_FORMAT' })
    emergency_authkey = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        username = attrs.get('username')
        emergency_authkey = attrs.get('emergency_authkey')


        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            msg = _("Username or emergency code incorrect.")
            raise exceptions.ValidationError(msg)

        emergency_codes = Emergency_Code.objects.filter(user_id=user.id)

        valid_emergency_code = None

        for emergency_code in emergency_codes:
            if not check_password(emergency_authkey, emergency_code.emergency_authkey):
                continue
            valid_emergency_code = emergency_code
            break

        if not valid_emergency_code:
            msg = _("Username or emergency code incorrect.")
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        attrs['emergency_code'] = valid_emergency_code

        return attrs