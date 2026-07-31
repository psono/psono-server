import nacl.encoding
from django.core.paginator import EmptyPage, Paginator
from django.db.models import Count, Q
from django.utils import timezone
from nacl.public import PrivateKey
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import (
    CreateFileserverClusterSerializer,
    DeleteFileserverClusterSerializer,
    ReadFileserverClusterSerializer,
    UpdateFileserverClusterSerializer,
)
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Fileserver_Cluster
from restapi.utils import encrypt_with_db_secret


class FileserverClusterView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    allowed_methods = ("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD")

    def get_serializer_class(self):
        if self.request.method == "GET":
            return ReadFileserverClusterSerializer
        elif self.request.method == "POST":
            return CreateFileserverClusterSerializer
        elif self.request.method == "PUT":
            return UpdateFileserverClusterSerializer
        elif self.request.method == "DELETE":
            return DeleteFileserverClusterSerializer
        return Serializer

    def get_link_info(self, link):
        return {
            "id": link.id,
            "create_date": link.create_date,
            "write_date": link.write_date,
            "cluster_id": link.cluster_id,
            "cluster_title": link.cluster.title,
            "shard_id": link.shard_id,
            "shard_title": link.shard.title,
            "read": link.read,
            "write": link.write,
            "delete_capability": link.delete_capability,
            "allow_link_shares": link.allow_link_shares,
        }

    def get_fileserver_info(self, fileserver):
        return {
            "id": fileserver.id,
            "create_date": fileserver.create_date,
            "write_date": fileserver.write_date,
            "create_ip": fileserver.create_ip,
            "cluster_id": fileserver.fileserver_cluster_id,
            "cluster_title": fileserver.fileserver_cluster.title,
            "public_key": fileserver.public_key,
            "url": fileserver.url,
            "version": fileserver.version,
            "hostname": fileserver.hostname,
            "read": fileserver.read,
            "write": fileserver.write,
            "delete_capability": fileserver.delete_capability,
            "allow_link_shares": fileserver.allow_link_shares,
            "valid_till": fileserver.valid_till,
            "alive": fileserver.valid_till > timezone.now(),
        }

    def get(self, request, cluster_id=None, *args, **kwargs):
        """
        Returns a list of all fileserver clusters or the details of a single cluster
        """

        serializer = ReadFileserverClusterSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        if cluster_id:
            cluster = serializer.validated_data.get("cluster")

            links = []
            for link in (
                cluster.links.select_related("cluster", "shard")
                .all()
                .order_by("shard__title")
            ):
                links.append(self.get_link_info(link))

            fileservers = []
            for fileserver in cluster.members.select_related(
                "fileserver_cluster"
            ).order_by("hostname"):
                fileservers.append(self.get_fileserver_info(fileserver))

            return Response(
                {
                    "id": cluster.id,
                    "create_date": cluster.create_date,
                    "write_date": cluster.write_date,
                    "title": cluster.title,
                    "file_size_limit": cluster.file_size_limit,
                    "links": links,
                    "fileservers": fileservers,
                },
                status=status.HTTP_200_OK,
            )

        else:
            page = serializer.validated_data.get("page")
            page_size = serializer.validated_data.get("page_size")
            ordering = serializer.validated_data.get("ordering")
            search = serializer.validated_data.get("search")

            cluster_qs = Fileserver_Cluster.objects.annotate(
                shard_count=Count("links", distinct=True),
                member_count=Count("members", distinct=True),
                live_member_count=Count(
                    "members",
                    filter=Q(members__valid_till__gt=timezone.now()),
                    distinct=True,
                ),
            )

            if search:
                cluster_qs = cluster_qs.filter(title__icontains=search)
            if ordering:
                cluster_qs = cluster_qs.order_by(ordering)

            count = None
            if page_size:
                paginator = Paginator(cluster_qs, page_size)
                count = paginator.count
                try:
                    chosen_page = paginator.page(page)
                    cluster_qs = chosen_page.object_list
                except EmptyPage:
                    cluster_qs = []

            clusters = []
            for cluster in cluster_qs:
                clusters.append(
                    {
                        "id": cluster.id,
                        "create_date": cluster.create_date,
                        "write_date": cluster.write_date,
                        "title": cluster.title,
                        "file_size_limit": cluster.file_size_limit,
                        "shard_count": cluster.shard_count,
                        "member_count": cluster.member_count,
                        "live_member_count": cluster.live_member_count,
                    }
                )

            return Response(
                {"count": count, "clusters": clusters}, status=status.HTTP_200_OK
            )

    def post(self, request, *args, **kwargs):
        """
        Creates a fileserver cluster
        """

        serializer = CreateFileserverClusterSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        title = serializer.validated_data.get("title")
        file_size_limit = serializer.validated_data.get("file_size_limit")

        private_key = PrivateKey.generate()
        auth_private_key = private_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        auth_public_key = private_key.public_key.encode(
            encoder=nacl.encoding.HexEncoder
        ).decode()

        cluster = Fileserver_Cluster.objects.create(
            title=title,
            file_size_limit=file_size_limit,
            auth_private_key=encrypt_with_db_secret(auth_private_key),
            auth_public_key=encrypt_with_db_secret(auth_public_key),
        )

        return Response({"id": cluster.id}, status=status.HTTP_201_CREATED)

    def put(self, request, *args, **kwargs):
        """
        Updates a fileserver cluster
        """

        serializer = UpdateFileserverClusterSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        cluster = serializer.validated_data.get("cluster")
        cluster.title = serializer.validated_data.get("title")
        cluster.file_size_limit = serializer.validated_data.get("file_size_limit")
        cluster.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a fileserver cluster
        """

        serializer = DeleteFileserverClusterSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        cluster = serializer.validated_data.get("cluster")
        cluster.delete()

        return Response({}, status=status.HTTP_200_OK)
