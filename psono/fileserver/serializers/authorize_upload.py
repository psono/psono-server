import re
from django.utils import timezone
from django.conf import settings

from rest_framework import serializers, exceptions

from restapi.models import File_Transfer, Fileserver_Cluster_Member_Shard_Link
from restapi.parsers import decrypt
from restapi.fields import UUIDField

from datetime import timedelta
import json

class FileserverAuthorizeUploadSerializer(serializers.Serializer):

    file_transfer_id = UUIDField(required=True)
    ticket = serializers.CharField(required=True)
    ticket_nonce = serializers.CharField(required=True)
    chunk_size = serializers.IntegerField(required=True, min_value=0, max_value=128 * 1024 * 1024 + 40)
    hash_checksum = serializers.CharField(required=True)
    ip_address = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_transfer_id = attrs.get('file_transfer_id')
        ticket_encrypted = attrs.get('ticket')
        ticket_nonce = attrs.get('ticket_nonce')
        chunk_size = attrs.get('chunk_size', 0)
        hash_checksum = attrs.get('hash_checksum', '').lower()
        ip_address = attrs.get('ip_address')

        try:
            file_transfer = File_Transfer.objects.select_related('user').\
                only('chunk_count', 'size', 'chunk_count_transferred', 'size_transferred', 'file_id', 'shard_id', 'secret_key', 'user__is_active', 'user_id').\
                get(pk=file_transfer_id, type='upload', create_date__gte=timezone.now()-timedelta(hours=12))
        except File_Transfer.DoesNotExist:
            msg = 'Filetransfer does not exist.'
            raise exceptions.ValidationError(msg)

        if not file_transfer.user.is_active:
            msg = 'User inactive.'
            raise exceptions.ValidationError(msg)

        try:
            ticket_json = decrypt(file_transfer.secret_key, ticket_encrypted, ticket_nonce)
        except:
            msg = 'Malformed ticket. Decryption failed.'
            raise exceptions.ValidationError(msg)

        ticket = json.loads(ticket_json)

        if 'chunk_position' not in ticket:
            msg = 'Malformed ticket. Chunk Position missing.'
            raise exceptions.ValidationError(msg)

        if 'hash_checksum' not in ticket:
            msg = 'Malformed ticket. Blake2b hash missing.'
            raise exceptions.ValidationError(msg)

        chunk_position = ticket['chunk_position']
        hash_checksum_ticket = ticket['hash_checksum'].lower()

        if not re.match('^[0-9a-f]*$', hash_checksum, re.IGNORECASE):
            msg = 'HASH_CHECKSUM_NOT_IN_HEX_REPRESENTATION'
            raise exceptions.ValidationError(msg)

        if hash_checksum_ticket != hash_checksum:
            msg = 'Chunk corrupted.'
            raise exceptions.ValidationError(msg)

        count_cmsl = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member')\
            .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                 shard__active=True, member=self.context['request'].user, shard_id=file_transfer.shard_id).count()

        if count_cmsl != 1:
            msg = 'Permission denied.'
            raise exceptions.ValidationError(msg)

        if file_transfer.chunk_count_transferred + 1 > file_transfer.chunk_count:
            msg = 'Chunk count exceeded.'
            raise exceptions.ValidationError(msg)

        if file_transfer.size_transferred + chunk_size > file_transfer.size:
            msg = 'Chunk size exceeded.'
            raise exceptions.ValidationError(msg)

        attrs['file_transfer'] = file_transfer
        attrs['user_id'] = file_transfer.user_id
        attrs['chunk_position'] = chunk_position
        attrs['chunk_size'] = chunk_size
        attrs['hash_checksum'] = hash_checksum

        return attrs
