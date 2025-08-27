from django.conf import settings

from ..models import Ivalt
from rest_framework import serializers, exceptions
from ..fields import UUIDField


class DeleteIvaltSerializer(serializers.Serializer):
    ivalt_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        ivalt_id = attrs.get('ivalt_id')

        # check if ivalt mobile no exists
        try:
            ivalt = Ivalt.objects.get(pk=ivalt_id, user=self.context['request'].user)
        except Ivalt.DoesNotExist:
            msg = 'NO_PERMISSION_OR_NOT_EXIST'
            raise exceptions.ValidationError(msg)

        attrs['ivalt'] = ivalt

        return attrs
