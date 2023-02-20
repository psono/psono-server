import re
from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, exceptions

from restapi.models import File_Chunk

class FileRepositoryDownloadSerializer(serializers.Serializer):

    hash_checksum = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        hash_checksum = attrs.get('hash_checksum', '').lower()

        file_transfer = self.context['request'].auth

        if not re.match('^[0-9a-f]*$', hash_checksum, re.IGNORECASE):
            msg = 'HASH_CHECKSUM_NOT_IN_HEX_REPRESENTATION'
            raise exceptions.ValidationError(msg)

        try:
            file_chunk = File_Chunk.objects.get(hash_checksum=hash_checksum, file_id=file_transfer.file_id)
        except File_Chunk.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if file_transfer.chunk_count_transferred + 1 > file_transfer.chunk_count:
            msg = _('Chunk count exceeded.')
            raise exceptions.ValidationError(msg)

        if file_transfer.size_transferred + file_chunk.size > file_transfer.size:
            msg = _('Chunk size exceeded.')
            raise exceptions.ValidationError(msg)

        attrs['file_transfer'] = file_transfer
        attrs['file_chunk'] = file_chunk
        attrs['hash_checksum'] = hash_checksum

        return attrs
