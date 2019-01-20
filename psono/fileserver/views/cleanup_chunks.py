from django.db import transaction
from django.db.models import F
from django.utils import timezone
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from datetime import timedelta

from restapi.authentication import FileserverAuthentication
from restapi.utils import get_uuid_start_and_end
from ..permissions import IsFileserver
from ..app_settings import AuthorizeUploadSerializer
from restapi.models import Fileserver_Cluster_Member_Shard_Link, File_Chunk

class CleanupChunksView(GenericAPIView):

    authentication_classes = (FileserverAuthentication, )
    permission_classes = (IsFileserver,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')
    throttle_scope = 'fileserver_upload'

    def get(self, request, *args, **kwargs):

        shard_ids = Fileserver_Cluster_Member_Shard_Link.objects.filter(member=request.user, delete=True).values_list('shard_id', flat=True)

        links = Fileserver_Cluster_Member_Shard_Link.objects\
            .filter(shard_id__in=shard_ids, member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT))\
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
            shards[str(shard_id)] = list(File_Chunk.objects.values_list('hash_blake2b', flat=True).filter(pk__gte=start, pk__lte=end, file__delete_date__lte=timezone.now(), file__shard_id=shard_id))

        return Response({
            'shards': shards
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)