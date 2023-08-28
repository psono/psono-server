from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import File_Repository_Right
from ..utils import user_has_rights_on_file_repository


class DeleteFileRepositoryRightSerializer(serializers.Serializer):

    file_repository_right_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_repository_right_id = attrs.get('file_repository_right_id')

        try:
            file_repository_right = File_Repository_Right.objects.only('id', 'user_id', 'file_repository_id').get(pk=file_repository_right_id)
        except File_Repository_Right.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if file_repository_right.user_id != self.context['request'].user.id:
            # Its not his own file repository right (leave group functionality) check if the user has the necessary access
            # privileges for this file repository
            if not user_has_rights_on_file_repository(
                user_id=self.context['request'].user.id,
                file_repository_id=file_repository_right.file_repository_id,
                grant=True,
            ):
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        attrs['file_repository_right'] = file_repository_right

        return attrs