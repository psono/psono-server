from django.utils.translation import ugettext_lazy as _

from ..models import API_Key, API_Key_Secret
from rest_framework import serializers, exceptions
from ..fields import UUIDField


class RemoveSecretFromAPIKeySerializer(serializers.Serializer):

    api_key_secret_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        api_key_secret_id = attrs.get('api_key_secret_id')

        # check if api_key_secret exists
        try:
            api_key_secret = API_Key_Secret.objects.get(pk=api_key_secret_id)
        except API_Key_Secret.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # check if user owns the api key
        try:
            API_Key.objects.get(pk=api_key_secret.api_key_id, user=self.context['request'].user)
        except API_Key.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['api_key_secret'] = api_key_secret

        return attrs