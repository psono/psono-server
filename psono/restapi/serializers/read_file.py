from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.conf import settings
from rest_framework import serializers, exceptions
from ..models import File

from ..utils import user_has_rights_on_file

class ReadFileSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:

        file_id = self.context['request'].parser_context['kwargs'].get('file_id', False)

        # check if the file exists
        try:
            file = File.objects.get(pk=file_id)
        except File.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        # check if it has been marked for deletion
        if file.delete_date < timezone.now():
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        # check if the user has the necessary rights
        if not user_has_rights_on_file(self.context['request'].user.id, file_id, read=True):
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        # calculate the required credits and check if the user has those
        credit = 0
        if settings.CREDIT_COSTS_DOWNLOAD > 0:
            credit = settings.CREDIT_COSTS_DOWNLOAD * file.size / 1024 / 1024 / 1024

        if credit > 0 and self.context['request'].user.credit < credit:
            msg = _("INSUFFICIENT_FUNDS")
            raise exceptions.ValidationError(msg)

        attrs['file'] = file
        attrs['credit'] = credit

        return attrs

