from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Fileserver_Cluster


class UpdateFileserverClusterSerializer(serializers.Serializer):
    cluster_id = UUIDField(required=True)
    title = serializers.CharField(max_length=256, required=True, trim_whitespace=True)
    file_size_limit = serializers.IntegerField(
        required=True, min_value=0, max_value=9223372036854775807
    )

    def validate(self, attrs: dict) -> dict:
        cluster_id = attrs.get("cluster_id")

        try:
            cluster = Fileserver_Cluster.objects.get(pk=cluster_id)
        except Fileserver_Cluster.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["cluster"] = cluster

        return attrs
