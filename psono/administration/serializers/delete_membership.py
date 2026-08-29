from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import User_Group_Membership
from .admin_access import AdminCapabilitySerializerMixin


class DeleteMembershipSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "groups.memberships.manage"

    membership_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        membership_id = attrs.get("membership_id")

        try:
            membership = User_Group_Membership.objects.get(id=membership_id)
        except User_Group_Membership.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(group=membership.group)

        attrs["membership"] = membership

        return attrs
