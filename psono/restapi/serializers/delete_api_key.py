
from ..models import API_Key
from rest_framework import serializers, exceptions
from ..fields import UUIDField


class DeleteAPIKeySerializer(serializers.Serializer):

    api_key_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        api_key_id = attrs.get('api_key_id')

        # check if api_key exists
        try:
            api_key = API_Key.objects.get(pk=api_key_id, user=self.context['request'].user)
        except API_Key.DoesNotExist:
            msg = "API_KEY_DOES_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['api_key'] = api_key

        return attrs