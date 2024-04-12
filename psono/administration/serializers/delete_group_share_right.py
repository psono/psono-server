from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Group_Share_Right

class DeleteGroupShareRightSerializer(serializers.Serializer):
    group_share_right_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        group_share_right_id = attrs.get('group_share_right_id')

        try:
            group_share_right = Group_Share_Right.objects.get(pk=group_share_right_id)
        except Group_Share_Right.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['group_share_right'] = group_share_right

        return attrs
