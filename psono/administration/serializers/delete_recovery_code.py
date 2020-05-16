from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Recovery_Code

class DeleteRecoveryCodeSerializer(serializers.Serializer):
    recovery_code_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        recovery_code_id = attrs.get('recovery_code_id')

        try:
            recovery_code = Recovery_Code.objects.get(pk=recovery_code_id)
        except Recovery_Code.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['recovery_code'] = recovery_code

        return attrs
