from rest_framework import serializers, exceptions
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError

from ..utils import user_has_rights_on_secret

from ..models import Secret_History

class ReadHistorySerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        secret_history_id = self.context['request'].parser_context['kwargs'].get('secret_history_id', False)

        if not secret_history_id:
            msg = _('Secret History ID has not been provided')
            raise exceptions.ValidationError(msg)

        try:
            secret_history = Secret_History.objects.get(pk=secret_history_id)
        except ValidationError:
            msg = _('Secret History ID is badly formed and no secret_history_id')
            raise exceptions.ValidationError(msg)
        except Secret_History.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if not user_has_rights_on_secret(self.context['request'].user.id, secret_history.secret.id, True, None):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)


        attrs['secret_history'] = secret_history

        return attrs