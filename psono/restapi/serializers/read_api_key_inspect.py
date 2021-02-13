from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import API_Key_Secret, API_Key


class ReadAPIKeyInspectSerializer(serializers.Serializer):
    api_key_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        api_key_id = attrs.get('api_key_id')

        try:
            api_key = API_Key.objects.select_related('user').get(id=api_key_id, active=True, user__is_active=True)
        except API_Key.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        api_key_secrets = API_Key_Secret.objects.filter(api_key_id=api_key_id).only('secret_id').all()

        attrs['api_key_secrets'] = api_key_secrets
        attrs['api_key'] = api_key

        return attrs