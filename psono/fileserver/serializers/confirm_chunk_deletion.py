from django.utils import timezone
from django.conf import settings
from rest_framework import serializers, exceptions

from typing import List
from datetime import timedelta

from restapi.models import File_Chunk, Fileserver_Cluster_Member_Shard_Link


class FileserverConfirmChunkDeletionSerializer(serializers.Serializer):

    deleted_chunks = serializers.ListField(child=serializers.DictField(), required=True)

    def validate(self, attrs: dict) -> dict:

        deleted_chunks = attrs.get('deleted_chunks', [])

        hash_checksums: List[str] = []
        for c in deleted_chunks:
            if not Fileserver_Cluster_Member_Shard_Link.objects.select_related('member') \
                    .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                        shard__active=True, member=self.context['request'].user, shard_id=c['shard_id'], delete_capability=True, member__write=True) \
                    .exists():
                msg = 'Permission denied.'
                raise exceptions.ValidationError(msg)

            if File_Chunk.objects.only('id').filter(hash_checksum__in=c['chunks']).exclude(file__shard_id=c['shard_id']) \
                    .exists():
                msg = 'Permission denied.'
                raise exceptions.ValidationError(msg)

            hash_checksums = hash_checksums + c['chunks']

        attrs['hash_checksums'] = hash_checksums

        return attrs
