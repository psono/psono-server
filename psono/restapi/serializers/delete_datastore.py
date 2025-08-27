from django.conf import settings

from ..models import Data_Store
from rest_framework import serializers, exceptions
from ..fields import UUIDField


class DeleteDatastoreSerializer(serializers.Serializer):

    datastore_id = UUIDField(required=True)
    authkey = serializers.CharField(style={'input_type': 'password'}, required=True,
                                    max_length=settings.AUTH_KEY_LENGTH_BYTES*2,
                                    min_length=settings.AUTH_KEY_LENGTH_BYTES*2)

    def validate(self, attrs: dict) -> dict:

        datastore_id = attrs.get('datastore_id')

        # check if datastore exists
        try:
            datastore = Data_Store.objects.get(pk=datastore_id, user=self.context['request'].user)
        except Data_Store.DoesNotExist:
            msg = "DATASTORE_DOES_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # prevent deletion of the default datastore
        if datastore.is_default:
            msg = "CANNOT_DELETE_DEFAULT_DATASTORE"
            raise exceptions.ValidationError(msg)

        attrs['datastore'] = datastore

        return attrs