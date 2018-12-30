from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.conf import settings

from rest_framework import serializers, exceptions

from restapi.utils import get_cache, in_networks
from restapi.authentication import TokenAuthentication
from restapi.models import Token, File, Fileserver_Cluster_Member_Shard_Link
from restapi.parsers import decrypt

from datetime import timedelta
import json

class AuthorizeUploadSerializer(serializers.Serializer):


    token = serializers.CharField(required=True)
    ticket = serializers.CharField(required=True)
    ticket_nonce = serializers.CharField(required=True)
    chunk_size = serializers.IntegerField(required=True)
    hash_blake2b = serializers.CharField(required=True)
    ip_address = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        token = attrs.get('token')
        ticket_encrypted = attrs.get('ticket')
        ticket_nonce = attrs.get('ticket_nonce')
        chunk_size = attrs.get('chunk_size')
        hash_blake2b = attrs.get('hash_blake2b')
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

        if 'file_id' not in ticket:
            msg = _('Malformed ticket. File ID missing.')
            raise exceptions.ValidationError(msg)

        if 'shard_id' not in ticket:
            msg = _('Malformed ticket. Shard ID missing.')
            raise exceptions.ValidationError(msg)

        if 'chunk_position' not in ticket:
            msg = _('Malformed ticket. Chunk Position missing.')
            raise exceptions.ValidationError(msg)

        if 'hash_blake2b' not in ticket:
            msg = _('Malformed ticket. Blake2b hash missing.')
            raise exceptions.ValidationError(msg)

        chunk_size_limit = 128 * 1024 * 1024 + 40
        if chunk_size > chunk_size_limit:
            msg = _("Chunk size exceeds limit.")
            raise exceptions.ValidationError(msg)

        shard_id = ticket['shard_id']
        file_id = ticket['file_id']
        chunk_position = ticket['chunk_position']
        hash_blake2b_ticket = ticket['hash_blake2b']

        if hash_blake2b_ticket != hash_blake2b:
            msg = _('Chunk corrupted.')
            raise exceptions.ValidationError(msg)

        cluster_member_shard_link_objs = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member')\
            .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                 shard__active=True, member=self.context['request'].user, shard_id=shard_id)\
            .only('write', 'ip_write_blacklist', 'ip_write_whitelist', 'member__write')

        if len(cluster_member_shard_link_objs) != 1:
            msg = _('Permission denied.')
            raise exceptions.ValidationError(msg)

        cmsl = cluster_member_shard_link_objs[0]

        if not cmsl.write or not cmsl.member.write:
            msg = _('Permission denied.')
            raise exceptions.ValidationError(msg)

        ip_write_whitelist = json.loads(cmsl.ip_write_whitelist)
        ip_write_blacklist = json.loads(cmsl.ip_write_blacklist)

        has_write_whitelist = len(ip_write_whitelist) > 0
        write_blacklisted = in_networks(ip_address, ip_write_blacklist)
        write_whitelisted = in_networks(ip_address, ip_write_whitelist)

        if has_write_whitelist and not write_whitelisted:
            msg = _('Permission denied by IP.')
            raise exceptions.ValidationError(msg)

        if write_blacklisted:
            msg = _('Permission denied by IP.')
            raise exceptions.ValidationError(msg)

        # TODO Test user quota

        try:
            file = File.objects.get(pk=file_id, shard_id=shard_id, user=token.user_id)
        except File.DoesNotExist:
            msg = _('File does not exist.')
            raise exceptions.ValidationError(msg)


        attrs['file'] = file
        attrs['shard_id'] = shard_id
        attrs['chunk_position'] = chunk_position
        attrs['chunk_size'] = chunk_size

        return attrs
