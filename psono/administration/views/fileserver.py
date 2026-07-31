from django.core.paginator import EmptyPage, Paginator
from django.db.models import Q
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import ReadFileserverSerializer
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Fileserver_Cluster_Members


class FileserverView(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AdminPermission,)
    allowed_methods = ("GET", "OPTIONS", "HEAD")
    serializer_class = ReadFileserverSerializer

    def get_fileserver_info(self, fileserver, include_shards=False):
        fileserver_info = {
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

        if include_shards:
            shards = []
            for link in fileserver.member_links.select_related("shard").all():
                shards.append(
                    {
                        "id": link.id,
                        "shard_id": link.shard_id,
                        "shard_title": link.shard.title,
                        "read": link.read,
                        "write": link.write,
                        "delete_capability": link.delete_capability,
                        "allow_link_shares": link.allow_link_shares,
                        "ip_read_whitelist": link.ip_read_whitelist,
                        "ip_read_blacklist": link.ip_read_blacklist,
                        "ip_write_whitelist": link.ip_write_whitelist,
                        "ip_write_blacklist": link.ip_write_blacklist,
                    }
                )
            fileserver_info["shards"] = shards

        return fileserver_info

    def get(self, request, fileserver_id=None, *args, **kwargs):
        """
        Returns a list of all fileservers or the details of a single fileserver
        """

        serializer = ReadFileserverSerializer(
            data=request.data, context=self.get_serializer_context()
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        if fileserver_id:
            fileserver = serializer.validated_data.get("fileserver")
            fileserver_info = self.get_fileserver_info(fileserver, include_shards=True)

            return Response(fileserver_info, status=status.HTTP_200_OK)

        else:
            page = serializer.validated_data.get("page")
            page_size = serializer.validated_data.get("page_size")
            ordering = serializer.validated_data.get("ordering")
            search = serializer.validated_data.get("search")

            fileserver_qs = Fileserver_Cluster_Members.objects.select_related(
                "fileserver_cluster"
            ).filter(valid_till__gt=timezone.now())

            if search:
                fileserver_qs = fileserver_qs.filter(
                    Q(hostname__icontains=search)
                    | Q(url__icontains=search)
                    | Q(fileserver_cluster__title__icontains=search)
                )
            if ordering:
                if ordering.lstrip("-") == "cluster_title":
                    ordering = ordering.replace(
                        "cluster_title", "fileserver_cluster__title"
                    )
                fileserver_qs = fileserver_qs.order_by(ordering)

            count = None
            if page_size:
                paginator = Paginator(fileserver_qs, page_size)
                count = paginator.count
                try:
                    chosen_page = paginator.page(page)
                    fileserver_qs = chosen_page.object_list
                except EmptyPage:
                    fileserver_qs = []

            fileservers = []
            for fileserver in fileserver_qs:
                fileservers.append(self.get_fileserver_info(fileserver))

            return Response(
                {"count": count, "fileservers": fileservers},
                status=status.HTTP_200_OK,
            )
