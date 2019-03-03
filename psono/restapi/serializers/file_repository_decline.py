from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField

from ..models import File_Repository_Right

class FileRepositoryRightDeclineSerializer(serializers.Serializer):

    file_repository_right_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_repository_right_id = attrs.get('file_repository_right_id')

        try:
            file_repository_right_obj = File_Repository_Right.objects.get(pk=file_repository_right_id, user=self.context['request'].user, accepted=False)
        except File_Repository_Right.DoesNotExist:
            msg = _("You don't have permission to access it or it does not exist or you already accepted or declined this membership.")
            raise exceptions.ValidationError(msg)

        attrs['file_repository_right_obj'] = file_repository_right_obj

        return attrs