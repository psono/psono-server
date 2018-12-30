from rest_framework import serializers
from django.utils import timezone
from django.conf import settings

from datetime import timedelta
import ipaddress
import json

from ..models import (
    Fileserver_Cluster_Member_Shard_Link,
)

from ..utils import get_ip, in_networks

class ReadShardSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:

        ip_address = ipaddress.ip_address(get_ip(self.context['request']))

        cluster_member_shard_link_objs = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member', 'shard')\
            .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                    shard__active=True)\
            .only('read', 'write', 'ip_read_blacklist', 'ip_read_whitelist', 'ip_write_blacklist', 'ip_write_whitelist',
                  'member__url', 'member__read', 'member__write', 'member__public_key', 'shard__title', 'shard__description')

        shards = []

        for cmsl in cluster_member_shard_link_objs:
            cluster_member = cmsl.member

            read = cmsl.read and cluster_member.read
            write = cmsl.write and cluster_member.write

            ip_read_blacklist = json.loads(cmsl.ip_read_blacklist)
            ip_read_whitelist = json.loads(cmsl.ip_read_whitelist)

            has_read_whitelist = len(ip_read_whitelist) > 0
            read_blacklisted = in_networks(ip_address, ip_read_blacklist)
            read_whitelisted = in_networks(ip_address, ip_read_whitelist)

            if has_read_whitelist and not read_whitelisted:
                read = False

            if read_blacklisted:
                read = False

            ip_write_whitelist = json.loads(cmsl.ip_write_whitelist)
            ip_write_blacklist = json.loads(cmsl.ip_write_blacklist)

            has_write_whitelist = len(ip_write_blacklist) > 0
            write_blacklisted = in_networks(ip_address, ip_write_blacklist)
            write_whitelisted = in_networks(ip_address, ip_write_whitelist)

            if has_write_whitelist and not write_whitelisted:
                write = False

            if write_blacklisted:
                write = False

            if not read and not write:
                continue

            shards.append({
                'shard_title':  cmsl.shard.title,
                'shard_description':  cmsl.shard.description,
                'fileserver_public_key':  cmsl.member.public_key,
                'fileserver_url':  cmsl.member.url,
            })

        attrs['shards'] = shards

        return attrs