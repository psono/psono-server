from rest_framework import exceptions, serializers
from restapi.fields import UUIDField
from restapi.models import User_Share_Right

from .admin_access import AdminCapabilitySerializerMixin


class DeleteUserShareRightSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "users.shares.manage"

    user_share_right_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:
        try:
            user_share_right = User_Share_Right.objects.select_related("user").get(
                pk=attrs["user_share_right_id"]
            )
        except User_Share_Right.DoesNotExist:
            raise exceptions.ValidationError("NO_PERMISSION_OR_NOT_EXIST")

        self.validate_administrative_access(user=user_share_right.user)
        attrs["user_share_right"] = user_share_right
        return attrs
