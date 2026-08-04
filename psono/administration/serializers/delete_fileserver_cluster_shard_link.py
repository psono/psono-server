from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Fileserver_Cluster_Shard_Link


class DeleteFileserverClusterShardLinkSerializer(serializers.Serializer):
    link_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:
        link_id = attrs.get("link_id")

        try:
            link = Fileserver_Cluster_Shard_Link.objects.select_related("cluster").get(
                pk=link_id
            )
        except Fileserver_Cluster_Shard_Link.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["link"] = link

        return attrs
