from ..utils import user_has_rights_on_share

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import Data_Store

class CreateShareLinkSerializer(serializers.Serializer):

    link_id = serializers.UUIDField(required=True)
    share_id = serializers.UUIDField(required=True)
    parent_share_id = serializers.UUIDField(required=False)
    parent_datastore_id = serializers.UUIDField(required=False)

    def validate(self, attrs: dict) -> dict:

        link_id = attrs.get('link_id')
        share_id = attrs.get('share_id')
        parent_share_id = attrs.get('parent_share_id', None)
        parent_datastore_id = attrs.get('parent_datastore_id', None)

        if parent_share_id is None and parent_datastore_id is None:
            msg = _("Either parent share or datastore need to be specified.")
            raise exceptions.ValidationError(msg)

        if parent_share_id is not None and parent_datastore_id is not None:
            msg = _("Either parent share or datastore need to be specified, not both.")
            raise exceptions.ValidationError(msg)

        # check if datastore exists
        if parent_datastore_id is not None:
            try:
                Data_Store.objects.get(pk=parent_datastore_id, user=self.context['request'].user)
            except Data_Store.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        # check permissions on parent share (and if it exists)
        if parent_share_id is not None and not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # check permissions on share (and if it exists)
        if not user_has_rights_on_share(self.context['request'].user.id, share_id, grant=True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['link_id'] = link_id
        attrs['share_id'] = share_id
        attrs['parent_share_id'] = parent_share_id
        attrs['parent_datastore_id'] = parent_datastore_id

        return attrs

