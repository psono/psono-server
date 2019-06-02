from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.conf import settings

from rest_framework import serializers, exceptions

from restapi.models import File_Transfer, File_Chunk, Fileserver_Cluster_Member_Shard_Link
from restapi.parsers import decrypt
from restapi.fields import UUIDField

from datetime import timedelta
import json

class FileserverAuthorizeDownloadSerializer(serializers.Serializer):


    file_transfer_id = UUIDField(required=True)
    ticket = serializers.CharField(required=True)
    ticket_nonce = serializers.CharField(required=True)
    ip_address = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_transfer_id = attrs.get('file_transfer_id')
        ticket_encrypted = attrs.get('ticket')
        ticket_nonce = attrs.get('ticket_nonce')
        ip_address = attrs.get('ip_address')

        try:
            file_transfer = File_Transfer.objects.select_related('user').\
                only('chunk_count', 'size', 'chunk_count_transferred', 'size_transferred', 'file_id', 'shard_id', 'secret_key', 'user__is_active', 'user_id').\
                get(pk=file_transfer_id, type='download')
        except File_Transfer.DoesNotExist:
            msg = _('Filetransfer does not exist.')
            raise exceptions.ValidationError(msg)

        if not file_transfer.user.is_active:
            msg = _('User inactive.')
            raise exceptions.ValidationError(msg)

        try:
            ticket_json = decrypt(file_transfer.secret_key, ticket_encrypted, ticket_nonce)
        except:
            msg = _('Malformed ticket. Decryption failed.')
            raise exceptions.ValidationError(msg)

        ticket = json.loads(ticket_json)

        if 'hash_checksum' not in ticket:
            msg = _('Malformed ticket. Blake2b hash missing.')
            raise exceptions.ValidationError(msg)

        hash_checksum = ticket['hash_checksum'].lower()

        count_cmsl = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member')\
            .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                 shard__active=True, member=self.context['request'].user, shard_id=file_transfer.shard_id).count()

        if count_cmsl != 1:
            msg = _('Permission denied.')
            raise exceptions.ValidationError(msg)

        try:
            file_chunk = File_Chunk.objects.get(hash_checksum=hash_checksum)
        except File_Chunk.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        if file_transfer.chunk_count_transferred + 1 > file_transfer.chunk_count:
            msg = _('Chunk count exceeded.')
            raise exceptions.ValidationError(msg)

        if file_transfer.size_transferred + file_chunk.size > file_transfer.size:
            msg = _('Chunk size exceeded.')
            raise exceptions.ValidationError(msg)

        attrs['file_transfer'] = file_transfer
        attrs['user_id'] = file_transfer.user_id
        attrs['file_chunk'] = file_chunk
        attrs['hash_checksum'] = hash_checksum

        return attrs
