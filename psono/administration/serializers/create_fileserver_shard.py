from rest_framework import serializers
from restapi.fields import BooleanField
from .admin_access import AdminCapabilitySerializerMixin


class CreateFileserverShardSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "fileservers.manage"

    title = serializers.CharField(max_length=256, required=True, trim_whitespace=True)
    description = serializers.CharField(required=True, allow_blank=True)
    active = BooleanField(required=False, default=True)

    def validate(self, attrs):
        self.validate_global_administrative_access()
        return attrs
