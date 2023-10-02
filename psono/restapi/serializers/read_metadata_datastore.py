from rest_framework import serializers, exceptions
from django.core.exceptions import ValidationError

from ..models import Data_Store

class ReadMetadataDatastoreSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        datastore_id = self.context['request'].parser_context['kwargs'].get('datastore_id', False)

        try:
            datastore = Data_Store.objects.only('id', 'write_date').get(pk=datastore_id, user_id=self.context['request'].user.id)
        except ValidationError:
            msg = 'DATASTORE_ID_MALFORMED'
            raise exceptions.ValidationError(msg)
        except Data_Store.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['datastore'] = datastore

        return attrs