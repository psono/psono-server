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
            api_key_secret = API_Key_Secret.objects.get(pk=api_key_secret_id, api_key__user=self.context['request'].user)
        except API_Key_Secret.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['api_key_secret'] = api_key_secret

        return attrs