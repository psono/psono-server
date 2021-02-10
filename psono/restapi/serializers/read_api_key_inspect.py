from rest_framework import serializers
from ..fields import UUIDField
from ..models import API_Key_Secret


class ReadAPIKeyInspectSerializer(serializers.Serializer):
    api_key_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        api_key_id = attrs.get('api_key_id')

        api_key_secrets = API_Key_Secret.objects.filter(api_key_id=api_key_id, api_key__active=True, api_key__user__is_active=True).only('secret_id').all()

        attrs['api_key_secrets'] = api_key_secrets

        return attrs