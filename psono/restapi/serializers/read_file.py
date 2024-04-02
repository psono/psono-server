from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
from rest_framework import serializers, exceptions

from datetime import timedelta

from ..models import File, Fileserver_Cluster_Member_Shard_Link
from ..utils import user_has_rights_on_file, fileserver_access, get_ip

class ReadFileSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:

        file_id = self.context['request'].parser_context['kwargs'].get('file_id', False)
        credit = 0

        # check if the file exists
        try:
            file = File.objects.only('id', 'delete_date', 'delete_date', 'shard_id', 'file_repository_id', 'size', 'chunk_count').get(pk=file_id)
        except File.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check if it has been marked for deletion
        if file.delete_date and file.delete_date < timezone.now():
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check if the user has the necessary rights
        if not user_has_rights_on_file(self.context['request'].user.id, file_id, read=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if file.shard_id:
            cluster_member_shard_link_objs = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member')\
                .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                        shard__active=True, read=True, member__read=True, shard=file.shard)\
                .only('read', 'ip_read_blacklist', 'ip_read_whitelist', 'member__read')

            ip_address = get_ip(self.context['request'])
            cmsl_available = False
            for cmsl in cluster_member_shard_link_objs:
                if fileserver_access(cmsl, ip_address, read=True):
                    cmsl_available = True
                    break

            if not cmsl_available:
                msg = "NO_FILESERVER_AVAILABLE"
                raise exceptions.ValidationError(msg)

            # calculate the required credits and check if the user has those
            if settings.SHARD_CREDIT_COSTS_DOWNLOAD > 0:
                credit = settings.SHARD_CREDIT_COSTS_DOWNLOAD * file.size / 1024 / 1024 / 1024

            if credit > 0 and self.context['request'].user.credit < credit:
                msg = _("INSUFFICIENT_FUNDS")
                raise exceptions.ValidationError(msg)

        attrs['file'] = file
        attrs['credit'] = credit

        return attrs

