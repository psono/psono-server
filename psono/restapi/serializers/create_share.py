from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions

from ..utils import user_has_rights_on_share, get_datastore
from ..models import Share

class CreateShareSerializer(serializers.Serializer):

    link_id = serializers.UUIDField(required=True)
    data = serializers.CharField(required=True)
    data_nonce = serializers.CharField(required=True, max_length=64)
    parent_share_id = serializers.UUIDField(required=False)
    parent_datastore_id = serializers.UUIDField(required=False)
    key = serializers.CharField(required=True)
    key_nonce = serializers.CharField(max_length=64, required=True)
    key_type = serializers.CharField(default='asymmetric')

    def validate(self, attrs):
        parent_share_id = attrs.get('parent_share_id', None)
        parent_datastore_id = attrs.get('parent_datastore_id', None)

        parent_share = None
        parent_datastore = None

        if parent_share_id is not None:
            # check permissions on parent
            if not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

            try:
                parent_share = Share.objects.get(pk=parent_share_id)
            except Share.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

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