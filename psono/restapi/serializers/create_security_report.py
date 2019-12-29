from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions

from ..utils import authenticate
from ..fields import BooleanField

class CreateSecurityReportSerializer(serializers.Serializer):

    entries = serializers.ListField(child=serializers.DictField())
    check_haveibeenpwned = BooleanField()
    authkey = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs: dict) -> dict:
        authkey = attrs.get('authkey')

        if settings.DISABLE_CENTRAL_SECURITY_REPORTS:
            msg = _("CENTRAL_SECURITY_REPORTS_DISABLED")
            raise exceptions.ValidationError(msg)

        user, error_code = authenticate(username=self.context['request'].user.username, authkey=str(authkey))

        if not user:
            msg = _("PASSWORD_INCORRECT")
            raise exceptions.ValidationError(msg)

        return attrs