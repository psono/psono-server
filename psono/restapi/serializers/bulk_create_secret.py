from rest_framework import serializers, exceptions
from ..fields import UUIDField

from ..utils import user_has_rights_on_share, get_datastore


class BulkCreateSecretSingleSerializer(serializers.Serializer):

    data = serializers.CharField(required=True)
    data_nonce = serializers.CharField(required=True, max_length=64)
    callback_url = serializers.CharField(required=False, max_length=2048, default='', allow_blank=True)
    callback_user = serializers.CharField(required=False, max_length=128, default='', allow_blank=True)
    callback_pass = serializers.CharField(required=False, max_length=128, default='', allow_blank=True)
    link_id = UUIDField(required=True)

class BulkCreateSecretSerializer(serializers.Serializer):

    secrets = serializers.ListField(child=BulkCreateSecretSingleSerializer(), min_length=1)
    parent_share_id = UUIDField(required=False)
    parent_datastore_id = UUIDField(required=False)

    def validate(self, attrs: dict) -> dict:
        parent_share_id = attrs.get('parent_share_id', None)
        parent_datastore_id = attrs.get('parent_datastore_id', None)


        if parent_share_id is None and parent_datastore_id is None:
            msg = "EITHER_PARENT_DATASTORE_OR_SHARE_NEED_TO_BE_DEFINED"
            raise exceptions.ValidationError(msg)

        if parent_share_id is not None and parent_datastore_id is not None:
            msg = "EITHER_PARENT_DATASTORE_OR_SHARE_NEED_TO_BE_DEFINED_NOT_BOTH"
            raise exceptions.ValidationError(msg)

        if parent_share_id is not None:
            # check permissions on parent
            if not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        if parent_datastore_id is not None:
            parent_datastore = get_datastore(parent_datastore_id, self.context['request'].user)
            if not parent_datastore:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        attrs['parent_share_id'] = parent_share_id
        attrs['parent_datastore_id'] = parent_datastore_id

        return attrs