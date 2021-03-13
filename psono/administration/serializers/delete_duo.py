from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Duo

class DeleteDuoSerializer(serializers.Serializer):
    duo_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        duo_id = attrs.get('duo_id')

        try:
            duo = Duo.objects.get(pk=duo_id)
        except Duo.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['duo'] = duo

        return attrs
