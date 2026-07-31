from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import (
    CreateFileserverClusterShardLinkSerializer,
    DeleteFileserverClusterShardLinkSerializer,
    UpdateFileserverClusterShardLinkSerializer,
)
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Fileserver_Cluster_Shard_Link


class FileserverClusterShardLinkView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    allowed_methods = ("POST", "PUT", "DELETE", "OPTIONS", "HEAD")

    def get_serializer_class(self):
        if self.request.method == "POST":
            return CreateFileserverClusterShardLinkSerializer
        elif self.request.method == "PUT":
            return UpdateFileserverClusterShardLinkSerializer
        elif self.request.method == "DELETE":
            return DeleteFileserverClusterShardLinkSerializer
        return Serializer

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Links a fileserver shard to a cluster
        """

        serializer = CreateFileserverClusterShardLinkSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        link = Fileserver_Cluster_Shard_Link.objects.create(
            cluster=serializer.validated_data.get("cluster"),
            shard=serializer.validated_data.get("shard"),
            read=serializer.validated_data.get("read"),
            write=serializer.validated_data.get("write"),
            delete_capability=serializer.validated_data.get("delete_capability"),
            allow_link_shares=serializer.validated_data.get("allow_link_shares"),
        )

        return Response({"id": link.id}, status=status.HTTP_201_CREATED)

    def put(self, request, *args, **kwargs):
        """
        Updates a fileserver cluster shard link
        """

        serializer = UpdateFileserverClusterShardLinkSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        link = serializer.validated_data.get("link")
        link.read = serializer.validated_data.get("read")
        link.write = serializer.validated_data.get("write")
        link.delete_capability = serializer.validated_data.get("delete_capability")
        link.allow_link_shares = serializer.validated_data.get("allow_link_shares")
        link.save()

        link.cluster.members.all().delete()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Unlinks a fileserver shard from a cluster
        """

        serializer = DeleteFileserverClusterShardLinkSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        link = serializer.validated_data.get("link")
        cluster = link.cluster
        link.delete()
        cluster.members.all().delete()

        return Response({}, status=status.HTTP_200_OK)
