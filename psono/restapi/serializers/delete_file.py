from rest_framework import serializers, exceptions

from ..models import File
from ..utils import user_has_rights_on_secret
from ..fields import UUIDField


class DeleteFileSerializer(serializers.Serializer):
    """
    Serializer for deleting/detaching a file from a secret.
    This sets the file's secret_id to null so it can be cleaned up later.
    """

    file_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:
        file_id = attrs.get('file_id')

        # Check if the file exists
        try:
            file = File.objects.only('id', 'secret_id').get(pk=file_id)
        except File.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # Check if file has a secret (it's an attachment, not a file_link file)
        if not file.secret_id:
            msg = "FILE_NOT_ATTACHED_TO_SECRET"
            raise exceptions.ValidationError(msg)

        # Check if user has write permission on the secret
        if not user_has_rights_on_secret(self.context['request'].user.id, file.secret_id, write=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['file'] = file

        return attrs
