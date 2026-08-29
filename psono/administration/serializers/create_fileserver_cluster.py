from rest_framework import serializers
from .admin_access import AdminCapabilitySerializerMixin


class CreateFileserverClusterSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "fileservers.manage"

    title = serializers.CharField(max_length=256, required=True, trim_whitespace=True)
    file_size_limit = serializers.IntegerField(
        required=False, default=0, min_value=0, max_value=9223372036854775807
    )

    def validate(self, attrs):
        self.validate_global_administrative_access()
        return attrs
