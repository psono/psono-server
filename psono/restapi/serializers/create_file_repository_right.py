
from rest_framework import serializers, exceptions
from ..fields import UUIDField, BooleanField
from ..models import File_Repository_Right
from ..models import User
from ..utils import user_has_rights_on_file_repository

class CreateFileRepositoryRightSerializer(serializers.Serializer):

    user_id = UUIDField(required=True)
    file_repository_id = UUIDField(required=True)
    read = BooleanField(default=True)
    write = BooleanField(default=True)
    grant = BooleanField(default=False)

    def validate(self, attrs: dict) -> dict:

        user_id = attrs.get('user_id')
        file_repository_id = attrs.get('file_repository_id')

        if not user_has_rights_on_file_repository(
            user_id=self.context['request'].user.id,
            file_repository_id=file_repository_id,
            grant=True,
        ):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if not User.objects.filter(pk=user_id).exists():
            msg = "USER_DOES_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if File_Repository_Right.objects.filter(file_repository_id=file_repository_id, user_id=user_id).exists():
            msg = "USER_HAS_ALREADY_RIGHTS_FOR_FILE_REPOSITORY"
            raise exceptions.ValidationError(msg)

        return attrs
