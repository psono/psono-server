from rest_framework import serializers

from .admin_access import AdminCapabilitySerializerMixin


class ReadMembershipSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "groups.memberships.read"

    def validate(self, attrs):
        attrs["admin_access"] = self.validate_administrative_access()
        return attrs


class ReadRecoveryCodeSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "users.recovery.read"

    def validate(self, attrs):
        attrs["admin_access"] = self.validate_administrative_access()
        return attrs
