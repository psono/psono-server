from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField

from ..utils import user_has_rights_on_share, get_datastore
from ..models import Share

class CreateShareSerializer(serializers.Serializer):

    link_id = UUIDField(required=True)
    data = serializers.CharField(required=True)
    data_nonce = serializers.CharField(required=True, max_length=64)
    parent_share_id = UUIDField(required=False)
    parent_datastore_id = UUIDField(required=False)
    key = serializers.CharField(required=True)
    key_nonce = serializers.CharField(max_length=64, required=True)
    key_type = serializers.CharField(default='asymmetric')

    def validate(self, attrs: dict) -> dict:
        parent_share_id = attrs.get('parent_share_id', None)
        parent_datastore_id = attrs.get('parent_datastore_id', None)
        key_type = attrs.get('key_type')

        parent_share = None
        parent_datastore = None

        if key_type not in ['asymmetric', 'symmetric']:
            msg = _("Invalid Key Type")
            raise exceptions.ValidationError(msg)

        if parent_share_id is not None:
            # check permissions on parent (and if it exists)
            if not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

            parent_share = Share.objects.get(pk=parent_share_id)

        if parent_datastore_id is not None:
            parent_datastore = get_datastore(parent_datastore_id, self.context['request'].user)
            if not parent_datastore:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        if parent_share is None and parent_datastore is None:
            msg = _("Either parent share or datastore need to be specified.")
            raise exceptions.ValidationError(msg)

        attrs['parent_share_id'] = parent_share_id
        attrs['parent_datastore_id'] = parent_datastore_id

        return attrs