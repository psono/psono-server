from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from rest_framework import serializers, exceptions

from typing import List
from datetime import timedelta

from restapi.models import File_Chunk, Fileserver_Cluster_Member_Shard_Link


class FileserverConfirmChunkDeletionSerializer(serializers.Serializer):

    deleted_chunks = serializers.ListField(child=serializers.DictField(), required=True)

    def validate(self, attrs: dict) -> dict:

        deleted_chunks = attrs.get('deleted_chunks', [])

        hash_blake2bs: List[str] = []
        for c in deleted_chunks:
            if not Fileserver_Cluster_Member_Shard_Link.objects.select_related('member') \
                    .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                        shard__active=True, member=self.context['request'].user, shard_id=c['shard_id'], delete=True, member__write=True) \
                    .exists():
                msg = _('Permission denied.')
                raise exceptions.ValidationError(msg)

            if File_Chunk.objects.only('id').filter(hash_blake2b__in=c['chunks']).exclude(file__shard_id=c['shard_id']) \
                    .exists():
                msg = _('Permission denied.')
                raise exceptions.ValidationError(msg)

            hash_blake2bs = hash_blake2bs + c['chunks']

        attrs['hash_blake2bs'] = hash_blake2bs

        return attrs
