from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.conf import settings

from rest_framework import serializers, exceptions

from restapi.utils import get_cache, in_networks, user_has_rights_on_file
from restapi.authentication import TokenAuthentication
from restapi.models import Token, File_Transfer, File_Chunk, Fileserver_Cluster_Member_Shard_Link
from restapi.parsers import decrypt

from datetime import timedelta
import json

class AuthorizeDownloadSerializer(serializers.Serializer):


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

        if 'hash_blake2b' not in ticket:
            msg = _('Malformed ticket. Blake2b hash missing.')
            raise exceptions.ValidationError(msg)

        file_transfer_id = ticket['file_transfer_id']
        hash_blake2b = ticket['hash_blake2b']

        try:
            file_transfer = File_Transfer.objects.only('chunk_count', 'size', 'chunk_count_transferred', 'size_transferred', 'file_id', 'shard_id').get(pk=file_transfer_id, user=token.user_id)
        except File_Transfer.DoesNotExist:
            msg = _('Filetransfer does not exist.')
            raise exceptions.ValidationError(msg)

        cluster_member_shard_link_objs = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member')\
            .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                 shard__active=True, member=self.context['request'].user, shard_id=file_transfer.shard_id)\
            .only('read', 'ip_read_blacklist', 'ip_read_whitelist', 'member__read')

        if len(cluster_member_shard_link_objs) != 1:
            msg = _('Permission denied.')
            raise exceptions.ValidationError(msg)

        cmsl = cluster_member_shard_link_objs[0]

        if not cmsl.read or not cmsl.member.read:
            msg = _('Permission denied.')
            raise exceptions.ValidationError(msg)

        ip_read_whitelist = json.loads(cmsl.ip_read_whitelist)
        ip_read_blacklist = json.loads(cmsl.ip_read_blacklist)

        has_read_whitelist = len(ip_read_whitelist) > 0
        read_blacklisted = in_networks(ip_address, ip_read_blacklist)
        read_whitelisted = in_networks(ip_address, ip_read_whitelist)

        if has_read_whitelist and not read_whitelisted:
            msg = _('Permission denied by IP.')
            raise exceptions.ValidationError(msg)

        if read_blacklisted:
            msg = _('Permission denied by IP.')
            raise exceptions.ValidationError(msg)

        try:
            file_chunk = File_Chunk.objects.get(hash_blake2b=hash_blake2b)
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
        attrs['user_id'] = token.user_id
        attrs['file_chunk'] = file_chunk
        attrs['hash_blake2b'] = hash_blake2b

        return attrs
