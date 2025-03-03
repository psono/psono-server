from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Group

class UpdateGroupSerializer(serializers.Serializer):
    group_id = UUIDField(required=True)
    name = serializers.CharField(max_length=64, required=True)

    def validate(self, attrs: dict) -> dict:

        group_id = attrs.get('group_id')
        name = attrs.get('name')

        try:
            group = Group.objects.get(id=group_id)
        except Group.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if len(name) < 3:
            msg = 'NAME_TOO_SHORT'
            raise exceptions.ValidationError(msg)

        if '@' in name:
            msg = 'NAME_CONTAINS_FORBIDDEN_CHARACTERS'
            raise exceptions.ValidationError(msg)

        attrs['group'] = group

        return attrs
