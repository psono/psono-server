from rest_framework import serializers, exceptions
from ..models import Data_Store
from ..utils import authenticate
from ..fields import BooleanField, UUIDField

class CreateSecurityReportSerializer(serializers.Serializer):

    entries = serializers.ListField(child=serializers.DictField())
    check_haveibeenpwned = BooleanField()
    authkey = serializers.CharField(style={'input_type': 'password'}, required=False)

    def validate(self, attrs: dict) -> dict:
        authkey = attrs.get('authkey', '')

        master_password_validated = False
        if authkey:
            user, error_code = authenticate(username=self.context['request'].user.username, authkey=str(authkey))

            if user:
                master_password_validated = True

        attrs['master_password_validated'] = master_password_validated

        return attrs