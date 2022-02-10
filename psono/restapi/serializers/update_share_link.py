from ..utils import user_has_rights_on_share
from  more_itertools import unique_everseen

from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Data_Store, Share_Tree, Share

class UpdateShareLinkSerializer(serializers.Serializer):

    link_id = UUIDField(required=True)
    new_parent_share_id = UUIDField(required=False)
    new_parent_datastore_id = UUIDField(required=False)

    def validate(self, attrs: dict) -> dict:

        link_id = str(attrs.get('link_id')).replace("-", "")
        new_parent_share_id = attrs.get('new_parent_share_id', None)
        new_parent_datastore_id = attrs.get('new_parent_datastore_id', None)

        shares = []
        old_parents = []
        old_datastores = []

        for s in Share_Tree.objects.filter(path__match='*.' + link_id).all():
            shares.append(s.share_id)
            if s.parent_share_id:
                old_parents.append(s.parent_share_id)
            if s.parent_datastore_id:
                old_datastores.append(s.parent_datastore_id)

        # remove duplicates
        shares = list(unique_everseen(shares))
        old_parents = list(unique_everseen(old_parents))
        old_datastores = list(unique_everseen(old_datastores))

        if not shares and not old_parents and not old_datastores:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check grant permissions on share
        for share_id in shares:
            if not user_has_rights_on_share(self.context['request'].user.id, share_id, grant=True):
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        # check write permissions on old_parents
        for old_parent_share_id in old_parents:
            if not user_has_rights_on_share(self.context['request'].user.id, old_parent_share_id, write=True):
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        # check write permissions on old_datastores
        for old_datastore_id in old_datastores:
            if not Data_Store.objects.filter(pk=old_datastore_id, user=self.context['request'].user).exists():
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        # check permissions on new_parent_share (and if it exists)
        if new_parent_share_id and not user_has_rights_on_share(self.context['request'].user.id,
                                                                new_parent_share_id, write=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check if new parent datastore exists and belongs to the user
        if new_parent_datastore_id is not None:
            if not Data_Store.objects.filter(pk=new_parent_datastore_id, user=self.context['request'].user).exists():
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)


        attrs['shares'] = shares
        attrs['new_parent_share_id'] = new_parent_share_id
        attrs['new_parent_datastore_id'] = new_parent_datastore_id

        return attrs

