from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField, BooleanField
from ..models import File_Repository_Right

class UpdateFileRepositoryRightSerializer(serializers.Serializer):

    file_repository_right_id = UUIDField(required=True)
    read = BooleanField(default=True)
    write = BooleanField(default=True)
    grant = BooleanField(default=False)

    def validate(self, attrs: dict) -> dict:

        file_repository_right_id = attrs.get('file_repository_right_id')

        # Lets check if the file_repository_right exists
        try:
            file_repository_right = File_Repository_Right.objects.get(pk=file_repository_right_id)
        except File_Repository_Right.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        # Lets check if the current user can do that
        if not File_Repository_Right.objects.filter(user=self.context['request'].user, file_repository_id=file_repository_right.file_repository_id, grant=True, accepted=True).exists():
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        attrs['file_repository_right'] = file_repository_right

        return attrs
