from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Fileserver_Cluster


class DeleteFileserverClusterSerializer(serializers.Serializer):
    cluster_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:
        cluster_id = attrs.get("cluster_id")

        try:
            cluster = Fileserver_Cluster.objects.get(pk=cluster_id)
        except Fileserver_Cluster.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["cluster"] = cluster

        return attrs
