
from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Duo

class DeleteDuoSerializer(serializers.Serializer):

    duo_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        duo_id = attrs.get('duo_id')

        try:
            duo = Duo.objects.get(pk=duo_id, user=self.context['request'].user)
        except Duo.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        duo_count = Duo.objects.filter(user=self.context['request'].user, active=True).count()

        attrs['duo'] = duo
        attrs['duo_count'] = duo_count

        return attrs