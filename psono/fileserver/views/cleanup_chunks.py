from django.utils import timezone
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from datetime import timedelta

from restapi.authentication import FileserverAuthentication
from restapi.utils import get_uuid_start_and_end
from ..permissions import IsFileserver
from ..app_settings import FileserverConfirmChunkDeletionSerializer
from restapi.models import Fileserver_Cluster_Member_Shard_Link, File_Chunk, File

class CleanupChunksView(GenericAPIView):

    authentication_classes = (FileserverAuthentication, )
    permission_classes = (IsFileserver,)
    allowed_methods = ('GET', 'POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'fileserver_upload'

    def get(self, request, *args, **kwargs):
        """
        Returns the chunks that should be cleaned up by this fileserver

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 401
        :rtype:
        """

        # Get a list of all shards that are handled by this particular fileserver
        shard_ids = Fileserver_Cluster_Member_Shard_Link.objects.filter(member=request.user, delete_capability=True).values_list('shard_id', flat=True)

        # get a list of all fileservers, that are responsible for these shards with the capability to delete
        links = Fileserver_Cluster_Member_Shard_Link.objects\
            .filter(shard_id__in=shard_ids, member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT), delete_capability=True)\
            .values('member_id', 'shard_id', 'member__create_date')\
            .distinct()\
            .order_by('member__create_date')

        lookup_dict = {}
        for link in links:
            if link['shard_id'] not in lookup_dict:
                lookup_dict[link['shard_id']] = {
                    'count': 0,
                    'position': None
                }
            if link['member_id'] == request.user.id:
                lookup_dict[link['shard_id']]['position'] = lookup_dict[link['shard_id']]['count']
            lookup_dict[link['shard_id']]['count'] = lookup_dict[link['shard_id']]['count'] + 1

        shards = {}
        for shard_id, value in lookup_dict.items():
            if value['position'] is None:
                continue

            start, end = get_uuid_start_and_end(value['count'], value['position'])
            shards[str(shard_id)] = list(File_Chunk.objects.values_list('hash_checksum', flat=True).filter(pk__gte=start, pk__lte=end, file__delete_date__lte=timezone.now(), file__shard_id=shard_id))

        return Response({
            'shards': shards
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):

        serializer = FileserverConfirmChunkDeletionSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        hash_checksums = serializer.validated_data.get('hash_checksums')

        File_Chunk.objects.filter(hash_checksum__in=hash_checksums).delete()

        File.objects.filter(file_chunk__isnull=True, delete_date__lte=timezone.now()).delete()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)