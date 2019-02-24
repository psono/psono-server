from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions

from ..fields import UUIDField
from ..models import File_Transfer

class FileRepositoryUploadSerializer(serializers.Serializer):
    file_transfer_id = UUIDField(required=True)
    chunk_size = serializers.IntegerField(required=True)
    chunk_position = serializers.IntegerField(required=True)
    hash_checksum = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_transfer_id = attrs.get('file_transfer_id')
        chunk_size = attrs.get('chunk_size')
        hash_checksum = attrs.get('hash_checksum', '').lower()

        chunk_size_limit = 128 * 1024 * 1024 + 40
        if chunk_size > chunk_size_limit:
            msg = _("Chunk size exceeds limit.")
            raise exceptions.ValidationError(msg)
        if chunk_size < 40:
            msg = _("Chunk size too small.")
            raise exceptions.ValidationError(msg)

        try:
            file_transfer = File_Transfer.objects.select_related('file_repository').only('chunk_count', 'size', 'chunk_count_transferred', 'size_transferred', 'file_id', 'shard_id', 'file_repository__type', 'file_repository__data').get(pk=file_transfer_id, user=self.context['request'].user)
        except File_Transfer.DoesNotExist:
            msg = _('Filetransfer does not exist.')
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
