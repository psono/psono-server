from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import User
from .admin_access import AdminCapabilitySerializerMixin


class DeleteUserSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "users.delete"

    user_id = UUIDField(required=True)
    confirm_shared_ownership = serializers.BooleanField(required=False, default=False)

    def validate(self, attrs: dict) -> dict:

        user_id = attrs.get("user_id")

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        self.validate_administrative_access(user=user)
        if (
            not self.context["request"].user.is_superuser
            and user.tenant_memberships.count() > 1
            and not attrs["confirm_shared_ownership"]
        ):
            raise exceptions.ValidationError("SHARED_OWNERSHIP_CONFIRMATION_REQUIRED")

        attrs["user"] = user

        return attrs
