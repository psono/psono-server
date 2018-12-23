from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField

from ..utils import user_has_rights_on_share
from ..models import Share

class UpdateShareSerializer(serializers.Serializer):

    share_id = UUIDField(required=True)
    data = serializers.CharField(required=False)
    data_nonce = serializers.CharField(required=False, max_length=64)

    def validate(self, attrs: dict) -> dict:

        share_id = attrs.get('share_id', '')

        try:
            share = Share.objects.get(pk=share_id)
        except Share.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # check permissions on share
        if not user_has_rights_on_share(self.context['request'].user.id, share_id, write=True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)


        attrs['share'] = share
        attrs['data'] = attrs.get('data', False)
        attrs['data_nonce'] = attrs.get('data_nonce', False)

        return attrs