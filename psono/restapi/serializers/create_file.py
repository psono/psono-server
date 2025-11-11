from django.conf import settings
from django.utils import timezone
from rest_framework import serializers, exceptions

from datetime import timedelta

from ..fields import UUIDField
from ..models import Fileserver_Shard, Fileserver_Cluster_Member_Shard_Link, File_Repository
from ..utils import user_has_rights_on_share, get_datastore, fileserver_access, get_ip
from ..utils import calculate_user_rights_on_file_repository, user_has_rights_on_secret

class CreateFileSerializer(serializers.Serializer):

    shard_id = UUIDField(required=False)
    file_repository_id = UUIDField(required=False)
    chunk_count = serializers.IntegerField(required=True)
    size = serializers.IntegerField(required=False)
    link_id = UUIDField(required=False)
    parent_share_id = UUIDField(required=False)
    parent_datastore_id = UUIDField(required=False)
    parent_secret_id = UUIDField(required=False)

    def validate(self, attrs: dict) -> dict:

        shard_id = attrs.get('shard_id', None)
        file_repository_id = attrs.get('file_repository_id', None)
        parent_share_id = attrs.get('parent_share_id', None)
        parent_datastore_id = attrs.get('parent_datastore_id', None)
        parent_secret_id = attrs.get('parent_secret_id', None)
        link_id = attrs.get('link_id', None)
        size = attrs.get('size', 0)

        file_repository = None
        shard = None
        credit = 0


        if shard_id is None and file_repository_id is None:
            msg = "SELECT_EITHER_SHARD_OR_REPOSITORY"
            raise exceptions.ValidationError(msg)


        if shard_id is not None:
            # check if the shard exists
            try:
                shard = Fileserver_Shard.objects.only('id').get(pk=shard_id, active=True)
            except Fileserver_Shard.DoesNotExist:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        if file_repository_id is not None:
            # check if the file repository exists
            try:
                file_repository = File_Repository.objects.only('id', 'type', 'data').get(pk=file_repository_id, active=True)
            except File_Repository.DoesNotExist:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

            # check if the user has permission to upload a file
            rights = calculate_user_rights_on_file_repository(
                user_id=self.context['request'].user.id,
                file_repository_id=file_repository_id,
            )
            if not rights['shared']:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        # Validate parent: must have either (parent_secret_id) OR (link_id + parent_share/datastore)
        has_secret_parent = parent_secret_id is not None
        has_link = link_id is not None
        has_share_or_datastore = parent_share_id is not None or parent_datastore_id is not None

        if has_secret_parent and has_link:
            msg = "EITHER_PARENT_SECRET_OR_LINK_NOT_BOTH"
            raise exceptions.ValidationError(msg)

        if not has_secret_parent and not has_link:
            msg = "EITHER_PARENT_SECRET_OR_LINK_NEED_TO_BE_DEFINED"
            raise exceptions.ValidationError(msg)

        # If using secret attachment, validate write permission on secret
        if has_secret_parent:
            if not user_has_rights_on_secret(self.context['request'].user.id, parent_secret_id, write=True):
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)
            attrs['parent_secret_id'] = parent_secret_id

        # If using link (standalone file), validate parent_share_id OR parent_datastore_id
        if has_link:
            if parent_share_id is None and parent_datastore_id is None:
                msg = "EITHER_PARENT_DATASTORE_OR_SHARE_NEED_TO_BE_DEFINED"
                raise exceptions.ValidationError(msg)

            if parent_share_id is not None and parent_datastore_id is not None:
                msg = "EITHER_PARENT_DATASTORE_OR_SHARE_NEED_TO_BE_DEFINED_NOT_BOTH"
                raise exceptions.ValidationError(msg)

            if parent_share_id is not None:
                # check permissions on parent
                if not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
                    msg = "NO_PERMISSION_OR_NOT_EXIST"
                    raise exceptions.ValidationError(msg)

            if parent_datastore_id is not None:
                parent_datastore = get_datastore(parent_datastore_id, self.context['request'].user)
                if not parent_datastore:
                    msg = "NO_PERMISSION_OR_NOT_EXIST"
                    raise exceptions.ValidationError(msg)

        if shard_id:
            cluster_member_shard_link_objs = Fileserver_Cluster_Member_Shard_Link.objects.select_related('member')\
                .filter(member__valid_till__gt=timezone.now() - timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT),
                        shard__active=True, write=True, member__write=True, shard=shard)\
                .only('write', 'ip_write_blacklist', 'ip_write_whitelist', 'member__write')

            ip_address = get_ip(self.context['request'])
            cmsl_available = False
            for cmsl in cluster_member_shard_link_objs:
                if fileserver_access(cmsl, ip_address, write=True):
                    cmsl_available = True
                    break

            if not cmsl_available:
                msg = "NO_FILESERVER_AVAILABLE"
                raise exceptions.ValidationError(msg)

            if settings.SHARD_CREDIT_COSTS_UPLOAD > 0:
                credit = settings.SHARD_CREDIT_COSTS_UPLOAD * size / 1024 / 1024 / 1024

            if credit > 0 and self.context['request'].user.credit < credit:
                msg = "INSUFFICIENT_FUNDS"
                raise exceptions.ValidationError(msg)

        attrs['shard'] = shard
        attrs['file_repository'] = file_repository
        attrs['parent_share_id'] = parent_share_id
        attrs['parent_datastore_id'] = parent_datastore_id
        attrs['size'] = size
        attrs['credit'] = credit

        return attrs

