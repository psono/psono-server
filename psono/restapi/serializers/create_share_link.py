from ..utils import user_has_rights_on_share

from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Data_Store

class CreateShareLinkSerializer(serializers.Serializer):

    link_id = UUIDField(required=True)
    share_id = UUIDField(required=True)
    parent_share_id = UUIDField(required=False)
    parent_datastore_id = UUIDField(required=False)

    def validate(self, attrs: dict) -> dict:

        link_id = attrs.get('link_id', '')
        share_id = attrs.get('share_id', '')
        parent_share_id = attrs.get('parent_share_id', None)
        parent_datastore_id = attrs.get('parent_datastore_id', None)

        if parent_share_id is None and parent_datastore_id is None:
            msg = "EITHER_PARENT_DATASTORE_OR_SHARE_NEED_TO_BE_DEFINED"
            raise exceptions.ValidationError(msg)

        if parent_share_id is not None and parent_datastore_id is not None:
            msg = "EITHER_PARENT_DATASTORE_OR_SHARE_NEED_TO_BE_DEFINED_NOT_BOTH"
            raise exceptions.ValidationError(msg)

        # check if datastore exists
        if parent_datastore_id is not None:
            if not Data_Store.objects.filter(pk=parent_datastore_id, user=self.context['request'].user).exists():
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        # check permissions on parent share (and if it exists)
        if parent_share_id is not None and not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check permissions on share (and if it exists)
        if not user_has_rights_on_share(self.context['request'].user.id, share_id, grant=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['link_id'] = link_id
        attrs['share_id'] = share_id
        attrs['parent_share_id'] = parent_share_id
        attrs['parent_datastore_id'] = parent_datastore_id

        return attrs

