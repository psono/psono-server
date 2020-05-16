from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Group

class DeleteGroupSerializer(serializers.Serializer):
    group_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        group_id = attrs.get('group_id')

        try:
            group = Group.objects.get(id=group_id)
        except Group.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['group'] = group

        return attrs
