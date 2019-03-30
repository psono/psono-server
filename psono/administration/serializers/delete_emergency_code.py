from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Emergency_Code

class DeleteEmergencyCodeSerializer(serializers.Serializer):
    emergency_code_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        emergency_code_id = attrs.get('emergency_code_id')

        try:
            emergency_code = Emergency_Code.objects.get(pk=emergency_code_id)
        except Emergency_Code.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        attrs['emergency_code'] = emergency_code

        return attrs
