from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField, BooleanField
from ..models import File_Repository_Right

class CreateFileRepositoryRightSerializer(serializers.Serializer):

    user_id = UUIDField(required=True)
    file_repository_id = UUIDField(required=True)
    read = BooleanField(default=True)
    write = BooleanField(default=True)
    grant = BooleanField(default=False)

    def validate_file_repository_id(self, value):

        # This line also ensures that the desired group exists and that the user firing the request has admin rights
        if not File_Repository_Right.objects.filter(file_repository_id=value, user=self.context['request'].user, grant=True, accepted=True).exists():
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        return value

    def validate(self, attrs: dict) -> dict:

        user_id = attrs.get('user_id')
        file_repository_id = attrs.get('file_repository_id')

        if File_Repository_Right.objects.filter(file_repository_id=file_repository_id, user_id=user_id).exists():
            msg = _("USER_HAS_ALREADY_RIGHTS_FOR_FILE_REPOSITORY")
            raise exceptions.ValidationError(msg)

        return attrs
