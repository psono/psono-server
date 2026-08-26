from rest_framework import serializers, exceptions
from restapi.fields import BooleanField, UUIDField

from restapi.models import (
    Fileserver_Cluster,
    Fileserver_Cluster_Shard_Link,
    Fileserver_Shard,
)
from .admin_access import AdminCapabilitySerializerMixin


class CreateFileserverClusterShardLinkSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "fileservers.manage"

    cluster_id = UUIDField(required=True)
    shard_id = UUIDField(required=True)
    read = BooleanField(required=False, default=True)
    write = BooleanField(required=False, default=True)
    delete_capability = BooleanField(required=False, default=True)
    allow_link_shares = BooleanField(required=False, default=True)

    def validate(self, attrs: dict) -> dict:
        self.validate_global_administrative_access()
        cluster_id = attrs.get("cluster_id")
        shard_id = attrs.get("shard_id")

        try:
            cluster = Fileserver_Cluster.objects.get(pk=cluster_id)
            shard = Fileserver_Shard.objects.get(pk=shard_id)
        except (Fileserver_Cluster.DoesNotExist, Fileserver_Shard.DoesNotExist):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if Fileserver_Cluster_Shard_Link.objects.filter(
            cluster=cluster, shard=shard
        ).exists():
            msg = "LINK_ALREADY_EXISTS"
            raise exceptions.ValidationError(msg)

        attrs["cluster"] = cluster
        attrs["shard"] = shard

        return attrs
