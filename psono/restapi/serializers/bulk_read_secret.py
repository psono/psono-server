from rest_framework import serializers, exceptions

from ..fields import UUIDField
from ..utils import user_has_rights_on_secret
from ..models import Secret

class BulkReadSecretSerializer(serializers.Serializer):
    secret_ids = serializers.ListField(child=UUIDField())

    def validate(self, attrs: dict) -> dict:
        secret_ids = attrs.get('secret_ids')

        rights = user_has_rights_on_secret(self.context['request'].user.id, secret_ids, True, None)

        allowed_secret_ids = [secret_id for index, secret_id in enumerate(secret_ids) if rights[index]]

        attrs['secrets'] = Secret.objects.filter(pk__in=allowed_secret_ids)

        return attrs