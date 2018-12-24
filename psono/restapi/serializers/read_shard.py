from rest_framework import serializers, exceptions
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings

from datetime import timedelta
import ipaddress
from ..models import (
    Fileserver_Cluster_Member_Shard_Link,
)

from ..utils import get_ip

class ReadShardSerializer(serializers.Serializer):

    def in_networks(self, ip_address, networks):

        for network in networks:
            ip_network = ipaddress.ip_network(network)
            if ip_address in ip_network:
                return True

        return False

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

            has_read_whitelist = len(cmsl.ip_read_whitelist) > 0
            read_blacklisted = self.in_networks(ip_address, cmsl.ip_read_blacklist)
            read_whitelisted = self.in_networks(ip_address, cmsl.ip_read_whitelist)

            if has_read_whitelist and not read_whitelisted:
                read = False

            if read_blacklisted:
                read = False

            has_write_whitelist = len(cmsl.ip_write_whitelisted) > 0
            write_blacklisted = self.in_networks(ip_address, cmsl.ip_write_blacklist)
            write_whitelisted = self.in_networks(ip_address, cmsl.ip_write_whitelist)

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