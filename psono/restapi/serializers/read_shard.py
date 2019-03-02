from rest_framework import serializers
from django.utils import timezone
from django.conf import settings

from datetime import timedelta
from typing import List, Dict
import ipaddress

from ..models import (
    Fileserver_Cluster_Member_Shard_Link,
)

from ..utils import get_ip, fileserver_access

class ReadShardSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:

        ip_address = ipaddress.ip_address(get_ip(self.context['request']))

        cluster_member_shard_link_objs = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member', 'shard')\
            .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                    shard__active=True)\
            .only('read', 'write', 'ip_read_blacklist', 'ip_read_whitelist', 'ip_write_blacklist', 'ip_write_whitelist',
                  'member__url', 'member__read', 'member__write', 'member__public_key', 'shard__id', 'shard__title', 'shard__description')

        shards: List[Dict] = []
        shard_dic: Dict[str, Dict] = {}

        for cmsl in cluster_member_shard_link_objs:

            read = fileserver_access(cmsl, ip_address, read=True)
            write = fileserver_access(cmsl, ip_address, write=True)

            if cmsl.shard.id not in shard_dic:
                shard_dic[cmsl.shard.id] = {
                    'id':  cmsl.shard.id,
                    'shard_title':  cmsl.shard.title,
                    'shard_description':  cmsl.shard.description,
                    'fileserver': [],
                    'read': False,
                    'write': False,
                }

                shards.append(shard_dic[cmsl.shard.id])

            shard_dic[cmsl.shard.id]['fileserver'].append({
                'fileserver_public_key':  cmsl.member.public_key,
                'fileserver_url':  cmsl.member.url,
                'read':  read,
                'write':  write,
            })
            shard_dic[cmsl.shard.id]['read'] = shard_dic[cmsl.shard.id]['read'] or read
            shard_dic[cmsl.shard.id]['write'] = shard_dic[cmsl.shard.id]['write'] or write


        attrs['shards'] = shards

        return attrs