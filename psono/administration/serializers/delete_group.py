from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Group
from .admin_access import AdminCapabilitySerializerMixin


class DeleteGroupSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "groups.delete"

    group_id = UUIDField(required=True)
    confirm_shared_ownership = serializers.BooleanField(required=False, default=False)

    def validate(self, attrs: dict) -> dict:

        group_id = attrs.get("group_id")

        try:
            group = Group.objects.get(id=group_id)
        except Group.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(group=group)
        if (
            not self.context["request"].user.is_superuser
            and group.tenant_memberships.count() > 1
            and not attrs["confirm_shared_ownership"]
        ):
            raise exceptions.ValidationError("SHARED_OWNERSHIP_CONFIRMATION_REQUIRED")

        attrs["group"] = group

        return attrs
