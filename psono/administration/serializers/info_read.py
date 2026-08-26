from rest_framework import serializers

from .admin_access import AdminCapabilitySerializerMixin


class InfoReadSerializer(AdminCapabilitySerializerMixin, serializers.Serializer):
    required_capability = "system.read"

    def validate(self, attrs):
        self.validate_global_administrative_access()
        return attrs
