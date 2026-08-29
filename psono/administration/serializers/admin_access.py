from administration.utils.access import resolve_administrative_access
from rest_framework import serializers


class AdminCapabilitySerializerMixin:
    required_capability = None

    def validate_administrative_access(self, user=None, group=None, tenant_ids=None):
        request = self.context.get("request")
        access = resolve_administrative_access(
            request.user if request else None, self.required_capability
        )
        if access is None:
            raise serializers.ValidationError("ADMIN_PERMISSION_DENIED")
        if user is not None and not access.allows_user(user):
            raise serializers.ValidationError("NO_PERMISSION_OR_NOT_EXIST")
        if group is not None and not access.allows_group(group):
            raise serializers.ValidationError("NO_PERMISSION_OR_NOT_EXIST")
        if tenant_ids is not None and not access.allows_tenants(tenant_ids):
            raise serializers.ValidationError("ADMIN_PERMISSION_DENIED")
        return access

    def validate_global_administrative_access(self):
        access = self.validate_administrative_access()
        if not access.is_global:
            raise serializers.ValidationError("ADMIN_PERMISSION_DENIED")
        return access

    def validate_superuser(self):
        request = self.context.get("request")
        if request is None or not request.user.is_superuser:
            raise serializers.ValidationError("ADMIN_PERMISSION_DENIED")
