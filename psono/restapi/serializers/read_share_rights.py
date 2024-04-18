from rest_framework import serializers, exceptions
from django.core.exceptions import ValidationError

from ..utils import calculate_user_rights_on_share

from ..models import Share

class ReadShareRightsSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        share_id = self.context['request'].parser_context['kwargs'].get('share_id', False)

        if not share_id:
            msg = 'SHARE_ID_NOT_PROVIDED'
            raise exceptions.ValidationError(msg)

        try:
            share = Share.objects.get(pk=share_id)
        except ValidationError:
            msg = 'SHARE_ID_MALFORMED'
            raise exceptions.ValidationError(msg)
        except Share.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        own_share_rights = calculate_user_rights_on_share(self.context['request'].user.id, share_id)

        if not any([own_share_rights['read'], own_share_rights['write'], own_share_rights['grant']]):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['share'] = share
        attrs['own_share_rights'] = own_share_rights

        return attrs