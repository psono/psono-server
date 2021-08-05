from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions

from ..fields import UUIDField
from ..models import File_Transfer

class FileRepositoryUploadSerializer(serializers.Serializer):
    chunk_size = serializers.IntegerField(required=True)
    chunk_position = serializers.IntegerField(required=True)
    hash_checksum = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        chunk_size = attrs.get('chunk_size', 0)
        hash_checksum = attrs.get('hash_checksum', '').lower()

        file_transfer = self.context['request'].auth

        chunk_size_limit = 128 * 1024 * 1024
        if chunk_size > chunk_size_limit:
            msg = _("Chunk size exceeds limit.")
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
