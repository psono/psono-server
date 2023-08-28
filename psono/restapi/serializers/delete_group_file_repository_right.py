from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Group_File_Repository_Right
from ..models import User_Group_Membership
from ..utils import user_has_rights_on_file_repository


class DeleteGroupFileRepositoryRightSerializer(serializers.Serializer):

    group_file_repository_right_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        group_file_repository_right_id = attrs.get('group_file_repository_right_id')

        try:
            group_file_repository_right = Group_File_Repository_Right.objects.only('id', 'group_id', 'file_repository_id').get(pk=group_file_repository_right_id)
        except Group_File_Repository_Right.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if not User_Group_Membership.objects.filter(
                group_id=group_file_repository_right.group_id,
                user=self.context['request'].user,
                share_admin=True,
                accepted=True
        ).exists():
            # It's not a file repository right of a group where he is share admin (drop file repo functionality) check if
            # the user has the necessary access privileges for this file repository
            if not user_has_rights_on_file_repository(
                user_id=self.context['request'].user.id,
                file_repository_id=group_file_repository_right.file_repository_id,
                grant=True,
            ):
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        attrs['group_file_repository_right'] = group_file_repository_right

        return attrs