from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Group

class DeleteGroupSerializer(serializers.Serializer):

    group_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        group_id = attrs.get('group_id')

        # check if the group exists
        try:
            group = Group.objects.only('id').get(pk=group_id, members__user=self.context['request'].user, members__group_admin=True, members__accepted=True)
        except Group.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['group'] = group

        return attrs

