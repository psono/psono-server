from rest_framework import serializers, exceptions
from ..fields import UUIDField, BooleanField
from ..models import Group_File_Repository_Right
from ..utils import user_has_rights_on_file_repository

class UpdateGroupFileRepositoryRightSerializer(serializers.Serializer):

    group_file_repository_right_id = UUIDField(required=True)
    read = BooleanField(default=True)
    write = BooleanField(default=True)
    grant = BooleanField(default=False)

    def validate(self, attrs: dict) -> dict:

        group_file_repository_right_id = attrs.get('group_file_repository_right_id')

        # Let's check if the group_file_repository_right exists.
        try:
            group_file_repository_right = Group_File_Repository_Right.objects.get(pk=group_file_repository_right_id)
        except Group_File_Repository_Right.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # Let's check if the current user can do that
        if not user_has_rights_on_file_repository(
            user_id=self.context['request'].user.id,
            file_repository_id=group_file_repository_right.file_repository_id,
            grant=True,
        ):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['group_file_repository_right'] = group_file_repository_right

        return attrs
