from rest_framework import serializers, exceptions
from django.core.exceptions import ValidationError

from ..utils import calculate_user_rights_on_share

from ..models import Share

class ReadMetadataShareSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        share_id = self.context['request'].parser_context['kwargs'].get('share_id', False)

        try:
            share = Share.objects.only('id', 'write_date').get(pk=share_id)
        except ValidationError:
            msg = 'SHARE_ID_MALFORMED'
            raise exceptions.ValidationError(msg)
        except Share.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        rights = calculate_user_rights_on_share(self.context['request'].user.id, share.id)

        if not rights['read']:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['share'] = share

        return attrs