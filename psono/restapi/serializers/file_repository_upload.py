import re
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers, exceptions

class FileRepositoryUploadSerializer(serializers.Serializer):
    chunk_size = serializers.IntegerField(required=True, min_value=0, max_value=128 * 1024 * 1024 + 40)
    chunk_position = serializers.IntegerField(required=True, min_value=0, max_value=2147483647)
    hash_checksum = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        chunk_size = attrs.get('chunk_size', 0)
        hash_checksum = attrs.get('hash_checksum', '').lower()

        file_transfer = self.context['request'].auth

        if not re.match('^[0-9a-f]*$', hash_checksum, re.IGNORECASE):
            msg = 'HASH_CHECKSUM_NOT_IN_HEX_REPRESENTATION'
            raise exceptions.ValidationError(msg)

        if file_transfer.chunk_count_transferred + 1 > file_transfer.chunk_count:
            msg = _('Chunk count exceeded.')
            raise exceptions.ValidationError(msg)

        if file_transfer.size_transferred + chunk_size > file_transfer.size:
            msg = _('Chunk size exceeded.')
            raise exceptions.ValidationError(msg)

        attrs['hash_checksum'] = hash_checksum
        attrs['file_transfer'] = file_transfer

        return attrs
