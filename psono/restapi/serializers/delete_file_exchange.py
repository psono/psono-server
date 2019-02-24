from django.utils.translation import ugettext_lazy as _

from ..models import File_Exchange
from rest_framework import serializers, exceptions
from ..fields import UUIDField


class DeleteFileExchangeSerializer(serializers.Serializer):

    file_exchange_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        file_exchange_id = attrs.get('file_exchange_id')

        # check if file_exchange exists
        try:
            file_exchange = File_Exchange.objects.get(pk=file_exchange_id, file_exchange_user__user=self.context['request'].user, file_exchange_user__grant=True)
        except File_Exchange.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        attrs['file_exchange'] = file_exchange

        return attrs