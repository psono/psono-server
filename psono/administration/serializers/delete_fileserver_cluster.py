from rest_framework import serializers, exceptions
from restapi.fields import UUIDField

from restapi.models import Fileserver_Cluster
from .admin_access import AdminCapabilitySerializerMixin


class DeleteFileserverClusterSerializer(
    AdminCapabilitySerializerMixin, serializers.Serializer
):
    required_capability = "fileservers.manage"

    cluster_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:
        self.validate_global_administrative_access()
        cluster_id = attrs.get("cluster_id")

        try:
            cluster = Fileserver_Cluster.objects.get(pk=cluster_id)
        except Fileserver_Cluster.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["cluster"] = cluster

        return attrs
