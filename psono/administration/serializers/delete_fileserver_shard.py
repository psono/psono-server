from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Fileserver_Shard
from .admin_access import AdminCapabilitySerializerMixin


class DeleteFileserverShardSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "fileservers.manage"

    shard_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:
        self.validate_global_administrative_access()
        shard_id = attrs.get("shard_id")

        try:
            shard = Fileserver_Shard.objects.get(pk=shard_id)
        except Fileserver_Shard.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["shard"] = shard

        return attrs
