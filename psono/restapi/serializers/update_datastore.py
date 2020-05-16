from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField, BooleanField
from ..utils import get_datastore

class UpdateDatastoreSerializer(serializers.Serializer):

    datastore_id = UUIDField(required=True)
    name = serializers.CharField(max_length=64, required=False)
    data = serializers.CharField(required=False, allow_blank=True)
    data_nonce = serializers.CharField(required=False, allow_blank=True, max_length=64)
    secret_key = serializers.CharField(required=False, max_length=256)
    secret_key_nonce = serializers.CharField(required=False, max_length=64)
    description = serializers.CharField(max_length=64, required=False)
    is_default = BooleanField(required=False)

    def validate(self, attrs: dict) -> dict:

        datastore_id = attrs.get('datastore_id')

        datastore = get_datastore(datastore_id, self.context['request'].user)
        if not datastore:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['datastore'] = datastore

        return attrs
