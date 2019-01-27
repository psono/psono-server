from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..utils import user_has_rights_on_file
from ..fields import UUIDField
from ..models import File


class DeleteFileSerializer(serializers.Serializer):

    file_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:
        file_id = attrs.get('file_id', '')

        try:
            file = File.objects.get(pk=file_id)
        except File.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        if not user_has_rights_on_file(self.context['request'].user.id, file_id, write=True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['file'] = file

        return attrs

