from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions

from restapi.models import File_Transfer, File_Chunk

from ..fields import UUIDField

class FileExchangeDownloadSerializer(serializers.Serializer):

    file_transfer_id = UUIDField(required=True)
    hash_checksum = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_transfer_id = attrs.get('file_transfer_id')
        hash_checksum = attrs.get('hash_checksum', '').lower()

        try:
            file_transfer = File_Transfer.objects.only('chunk_count', 'size', 'chunk_count_transferred', 'size_transferred', 'file_id', 'shard_id', 'file_exchange__type', 'file_exchange__data').get(pk=file_transfer_id, user=self.context['request'].user)
        except File_Transfer.DoesNotExist:
            msg = _('Filetransfer does not exist.')
            raise exceptions.ValidationError(msg)

        try:
            file_chunk = File_Chunk.objects.get(hash_checksum=hash_checksum)
        except File_Chunk.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
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
