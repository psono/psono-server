from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField, BooleanField
from ..models import User_Group_Membership
from ..models import Group_File_Repository_Right
from ..utils import user_has_rights_on_file_repository

class CreateGroupFileRepositoryRightSerializer(serializers.Serializer):

    group_id = UUIDField(required=True)
    file_repository_id = UUIDField(required=True)
    read = BooleanField(default=True)
    write = BooleanField(default=True)
    grant = BooleanField(default=False)

    def validate(self, attrs: dict) -> dict:

        group_id = attrs.get('group_id')
        file_repository_id = attrs.get('file_repository_id')

        # This line also ensures that the desired group exists and that the user firing the request has admin rights
        if not user_has_rights_on_file_repository(
            user_id=self.context['request'].user.id,
            file_repository_id=file_repository_id,
            grant=True,
        ):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if not User_Group_Membership.objects.filter(
            group_id=group_id,
            user=self.context['request'].user,
            share_admin=True,
            accepted=True
        ).exists():
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if Group_File_Repository_Right.objects.filter(file_repository_id=file_repository_id, group_id=group_id).exists():
            msg = _("GROUP_HAS_ALREADY_RIGHTS_FOR_FILE_REPOSITORY")
            raise exceptions.ValidationError(msg)

        return attrs
