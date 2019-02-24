from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.conf import settings

from rest_framework import serializers, exceptions

from restapi.utils import get_cache
from restapi.authentication import TokenAuthentication
from restapi.models import Token, File_Transfer, File_Chunk, Fileserver_Cluster_Member_Shard_Link
from restapi.parsers import decrypt

from datetime import timedelta
import json

class FileserverRevokeDownloadSerializer(serializers.Serializer):


    token = serializers.CharField(required=True)
    ticket = serializers.CharField(required=True)
    ticket_nonce = serializers.CharField(required=True)
    ip_address = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        token = attrs.get('token')
        ticket_encrypted = attrs.get('ticket')
        ticket_nonce = attrs.get('ticket_nonce')
        ip_address = attrs.get('ip_address')

        token_hash = TokenAuthentication.user_token_to_token_hash(token)

        token = get_cache(Token, token_hash)

        if token is None:
            msg = _('Invalid token or not yet activated.')
            raise exceptions.ValidationError(msg)

        if not token.active:
            msg = _('Invalid token or not yet activated.')
            raise exceptions.ValidationError(msg)

        if token.valid_till < timezone.now():
            msg = _('Invalid token or not yet activated.')
            raise exceptions.ValidationError(msg)


        ticket_json = decrypt(token.secret_key, ticket_encrypted, ticket_nonce)
        ticket = json.loads(ticket_json)

        if 'file_transfer_id' not in ticket:
            msg = _('Malformed ticket. File transfer ID missing.')
            raise exceptions.ValidationError(msg)

        if 'hash_checksum' not in ticket:
            msg = _('Malformed ticket. Blake2b hash missing.')
            raise exceptions.ValidationError(msg)

        file_transfer_id = ticket['file_transfer_id']
        hash_checksum = ticket['hash_checksum'].lower()

        try:
            file_transfer = File_Transfer.objects.only('chunk_count', 'size', 'chunk_count_transferred', 'size_transferred', 'file_id', 'shard_id').get(pk=file_transfer_id, user=token.user_id)
        except File_Transfer.DoesNotExist:
            msg = _('Filetransfer does not exist.')
            raise exceptions.ValidationError(msg)

        count_cmsl = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member')\
            .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                 shard__active=True, member=self.context['request'].user, shard_id=file_transfer.shard_id).count()

        if count_cmsl != 1:
            msg = _('Permission denied.')
            raise exceptions.ValidationError(msg)

        try:
            file_chunk = File_Chunk.objects.get(hash_checksum=hash_checksum)
        except File_Chunk.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['file_transfer'] = file_transfer
        attrs['file_chunk'] = file_chunk

        return attrs
