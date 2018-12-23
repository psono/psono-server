from rest_framework import serializers, exceptions
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError

from ..utils import user_has_rights_on_secret

from ..models import Secret

class ReadSecretHistorySerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        secret_id = self.context['request'].parser_context['kwargs'].get('secret_id', False)

        if not secret_id:
            msg = _('Secret ID has not been provided')
            raise exceptions.ValidationError(msg)

        try:
            secret = Secret.objects.get(pk=secret_id)
        except ValidationError:
            msg = _('Secret ID is badly formed and no secret_id')
            raise exceptions.ValidationError(msg)
        except Secret.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        if not user_has_rights_on_secret(self.context['request'].user.id, secret.id, True, None):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)


        attrs['secret'] = secret

        return attrs