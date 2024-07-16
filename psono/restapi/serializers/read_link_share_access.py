from django.utils import timezone
from django.contrib.auth.hashers import check_password
from django.conf import settings
from rest_framework import serializers, exceptions

from datetime import timedelta
from typing import List, Dict

from ..fields import UUIDField
from ..models import Link_Share, Fileserver_Cluster_Member_Shard_Link
from ..utils import user_has_rights_on_secret, user_has_rights_on_file, fileserver_access, get_ip

class ReadLinkShareAccessSerializer(serializers.Serializer):

    link_share_id = UUIDField(required=True)
    passphrase = serializers.CharField(required=False, allow_null=True, allow_blank=True)

    def validate(self, attrs: dict) -> dict:

        link_share_id = attrs.get('link_share_id')
        passphrase = attrs.get('passphrase', '')

        credit = 0
        shards: List[Dict] = []
        shard_dic: Dict[str, Dict] = {}

        # Lets check if the current user can do that
        try:
            link_share = Link_Share.objects.select_related('secret', 'file', 'user').get(id=link_share_id)
        except Link_Share.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if link_share.valid_till is not None and link_share.valid_till<timezone.now():
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if link_share.allowed_reads is not None and link_share.allowed_reads<=0:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if link_share.passphrase is not None and not passphrase:
            msg = "PASSPHRASE_REQUIRED"
            raise exceptions.ValidationError(msg)

        if link_share.passphrase is not None and not check_password(passphrase, link_share.passphrase):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if not link_share.secret_id and not link_share.file_id:
            msg = "EITHER_SECRET_OR_FILE_REQUIRED"
            raise exceptions.ValidationError(msg)


        if not link_share.user.is_active:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if link_share.secret_id and not user_has_rights_on_secret(link_share.user_id, link_share.secret_id, read=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if link_share.file_id:

            if not user_has_rights_on_file(link_share.user_id, link_share.file_id, read=True):
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

            # check if it has been marked for deletion
            if link_share.file.delete_date and link_share.file.delete_date < timezone.now():
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

            if link_share.file.shard_id:
                cluster_member_shard_link_objs = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member', 'shard')\
                    .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                            shard__active=True, read=True, member__read=True, allow_link_shares=True, member__allow_link_shares=True, shard=link_share.file.shard)\
                    .only('read', 'ip_read_blacklist', 'ip_read_whitelist', 'member__read', 'member__public_key', 'member__url', 'shard__id', 'shard__title', 'shard__description')

                ip_address = get_ip(self.context['request'])
                for cmsl in cluster_member_shard_link_objs:
                    if not fileserver_access(cmsl, ip_address, read=True):
                        continue

                    if cmsl.shard.id not in shard_dic:
                        shard_dic[cmsl.shard.id] = {
                            'id': cmsl.shard.id,
                            'shard_title': cmsl.shard.title,
                            'shard_description': cmsl.shard.description,
                            'fileserver': [],
                            'read': True,
                        }

                        shards.append(shard_dic[cmsl.shard.id])

                    shard_dic[cmsl.shard.id]['fileserver'].append({
                        'fileserver_public_key': cmsl.member.public_key,
                        'fileserver_url': cmsl.member.url,
                        'read':  True,
                    })

                if len(shards) < 1:
                    msg = "NO_FILESERVER_AVAILABLE"
                    raise exceptions.ValidationError(msg)

                # calculate the required credits and check if the user has those
                if settings.SHARD_CREDIT_COSTS_DOWNLOAD > 0:
                    credit = settings.SHARD_CREDIT_COSTS_DOWNLOAD * link_share.file.size / 1024 / 1024 / 1024

                if credit > 0 and link_share.user.credit < credit:
                    msg = "INSUFFICIENT_FUNDS"
                    raise exceptions.ValidationError(msg)


        attrs['credit'] = credit
        attrs['link_share'] = link_share
        attrs['secret'] = link_share.secret
        attrs['file'] = link_share.file
        attrs['shards'] = shards

        return attrs
