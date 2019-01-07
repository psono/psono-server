from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Fileserver_Shard

from ..utils import user_has_rights_on_share, get_datastore

class CreateFileSerializer(serializers.Serializer):

    shard_id = UUIDField(required=True)
    chunk_count = serializers.IntegerField(required=False)
    size = serializers.IntegerField(required=False)
    link_id = UUIDField(required=True)
    parent_share_id = UUIDField(required=False)
    parent_datastore_id = UUIDField(required=False)

    def validate(self, attrs: dict) -> dict:

        shard_id = attrs.get('shard_id')
        parent_share_id = attrs.get('parent_share_id', None)
        parent_datastore_id = attrs.get('parent_datastore_id', None)
        size = attrs.get('size', None)

        # check if the shard exists
        try:
            shard = Fileserver_Shard.objects.only('id').get(pk=shard_id)
        except Fileserver_Shard.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)



        if parent_share_id is None and parent_datastore_id is None:
            msg = _("Either parent share or datastore need to be specified.")
            raise exceptions.ValidationError(msg)

        if parent_share_id is not None and parent_datastore_id is not None:
            msg = _("Either parent share or datastore need to be specified, not both.")
            raise exceptions.ValidationError(msg)

        if parent_share_id is not None:
            # check permissions on parent
            if not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        if parent_datastore_id is not None:
            parent_datastore = get_datastore(parent_datastore_id, self.context['request'].user)
            if not parent_datastore:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        # TODO Test user quota
        credit = 0
        if settings.CREDIT_COSTS_UPLOAD > 0:
            credit = settings.CREDIT_COSTS_UPLOAD * size / 1024 / 1024 / 1024

        if credit > 0 and self.context['request'].user.credit < credit:
            msg = _("Insufficient funds.")
            raise exceptions.ValidationError(msg)

        attrs['shard'] = shard
        attrs['parent_share_id'] = parent_share_id
        attrs['parent_datastore_id'] = parent_datastore_id
        attrs['size'] = size
        attrs['credit'] = credit

        return attrs

