from django.core.paginator import EmptyPage, Paginator
from django.db.models import Count, Q
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import (
    CreateFileserverShardSerializer,
    DeleteFileserverShardSerializer,
    ReadFileserverShardSerializer,
    UpdateFileserverShardSerializer,
)
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Fileserver_Shard


class FileserverShardView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    allowed_methods = ("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD")

    def get_serializer_class(self):
        if self.request.method == "GET":
            return ReadFileserverShardSerializer
        elif self.request.method == "POST":
            return CreateFileserverShardSerializer
        elif self.request.method == "PUT":
            return UpdateFileserverShardSerializer
        elif self.request.method == "DELETE":
            return DeleteFileserverShardSerializer
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

    def get(self, request, shard_id=None, *args, **kwargs):
        """
        Returns a list of all fileserver shards or the details of a single shard
        """

        serializer = ReadFileserverShardSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        if shard_id:
            shard = serializer.validated_data.get("shard")

            links = []
            for link in (
                shard.links.select_related("cluster", "shard")
                .all()
                .order_by("cluster__title")
            ):
                links.append(self.get_link_info(link))

            return Response(
                {
                    "id": shard.id,
                    "create_date": shard.create_date,
                    "write_date": shard.write_date,
                    "title": shard.title,
                    "description": shard.description,
                    "active": shard.active,
                    "links": links,
                },
                status=status.HTTP_200_OK,
            )

        else:
            page = serializer.validated_data.get("page")
            page_size = serializer.validated_data.get("page_size")
            ordering = serializer.validated_data.get("ordering")
            search = serializer.validated_data.get("search")

            shard_qs = Fileserver_Shard.objects.annotate(
                cluster_count=Count("links", distinct=True),
                member_count=Count("member_links__member", distinct=True),
            )

            if search:
                shard_qs = shard_qs.filter(
                    Q(title__icontains=search) | Q(description__icontains=search)
                )
            if ordering:
                shard_qs = shard_qs.order_by(ordering)

            count = None
            if page_size:
                paginator = Paginator(shard_qs, page_size)
                count = paginator.count
                try:
                    chosen_page = paginator.page(page)
                    shard_qs = chosen_page.object_list
                except EmptyPage:
                    shard_qs = []

            shards = []
            for shard in shard_qs:
                shards.append(
                    {
                        "id": shard.id,
                        "create_date": shard.create_date,
                        "write_date": shard.write_date,
                        "title": shard.title,
                        "description": shard.description,
                        "active": shard.active,
                        "cluster_count": shard.cluster_count,
                        "member_count": shard.member_count,
                    }
                )

            return Response(
                {"count": count, "shards": shards}, status=status.HTTP_200_OK
            )

    def post(self, request, *args, **kwargs):
        """
        Creates a fileserver shard
        """

        serializer = CreateFileserverShardSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        shard = Fileserver_Shard.objects.create(
            title=serializer.validated_data.get("title"),
            description=serializer.validated_data.get("description"),
            active=serializer.validated_data.get("active"),
        )

        return Response({"id": shard.id}, status=status.HTTP_201_CREATED)

    def put(self, request, *args, **kwargs):
        """
        Updates a fileserver shard
        """

        serializer = UpdateFileserverShardSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        shard = serializer.validated_data.get("shard")
        shard.title = serializer.validated_data.get("title")
        shard.description = serializer.validated_data.get("description")
        shard.active = serializer.validated_data.get("active")
        shard.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a fileserver shard
        """

        serializer = DeleteFileserverShardSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        shard = serializer.validated_data.get("shard")
        shard.delete()

        return Response({}, status=status.HTTP_200_OK)
