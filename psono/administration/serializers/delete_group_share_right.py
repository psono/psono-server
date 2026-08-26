from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Group_Share_Right
from .admin_access import AdminCapabilitySerializerMixin


class DeleteGroupShareRightSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "groups.shares.manage"

    group_share_right_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        group_share_right_id = attrs.get("group_share_right_id")

        try:
            group_share_right = Group_Share_Right.objects.get(pk=group_share_right_id)
        except Group_Share_Right.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(group=group_share_right.group)

        attrs["group_share_right"] = group_share_right

        return attrs
