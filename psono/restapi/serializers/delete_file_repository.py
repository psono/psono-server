from django.utils.translation import gettext_lazy as _

from ..models import File_Repository
from rest_framework import serializers, exceptions
from ..fields import UUIDField


class DeleteFileRepositorySerializer(serializers.Serializer):

    file_repository_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_repository_id = attrs.get('file_repository_id')

        # check if file_repository exists
        try:
            file_repository = File_Repository.objects.get(pk=file_repository_id, file_repository_right__user=self.context['request'].user, file_repository_right__accepted=True, file_repository_right__grant=True, file_repository_right__write=True)
        except File_Repository.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['file_repository'] = file_repository

        return attrs