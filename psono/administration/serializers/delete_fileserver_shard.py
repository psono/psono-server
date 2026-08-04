from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Fileserver_Shard


class DeleteFileserverShardSerializer(serializers.Serializer):
    shard_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:
        shard_id = attrs.get("shard_id")

        try:
            shard = Fileserver_Shard.objects.get(pk=shard_id)
        except Fileserver_Shard.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["shard"] = shard

        return attrs
