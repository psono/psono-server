from ..utils import user_has_rights_on_share
from  more_itertools import unique_everseen

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import File_Link, Data_Store


class MoveFileLinkSerializer(serializers.Serializer):

    link_id = UUIDField(required=True)
    new_parent_share_id = UUIDField(required=False)
    new_parent_datastore_id = UUIDField(required=False)

    def validate(self, attrs: dict) -> dict:
        link_id = attrs.get('link_id')
        new_parent_share_id = attrs.get('new_parent_share_id', None)
        new_parent_datastore_id = attrs.get('new_parent_datastore_id', None)

        if new_parent_share_id is None and new_parent_datastore_id is None:
            msg = _("No parent (share or datastore) has been provided as parent")
            raise exceptions.ValidationError(msg)

        files = []
        old_parents = []
        old_datastores = []

        for f in File_Link.objects.filter(link_id=link_id).all():
            files.append(f.file_id)
            if f.parent_share_id:
                old_parents.append(f.parent_share_id)
            if f.parent_datastore_id:
                old_datastores.append(f.parent_datastore_id)

        # remove duplicates
        files = list(unique_everseen(files))
        old_parents = list(unique_everseen(old_parents))
        old_datastores = list(unique_everseen(old_datastores))

        if not files and not old_parents and not old_datastores:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # check write permissions on old_parents
        for old_parent_share_id in old_parents:
            if not user_has_rights_on_share(self.context['request'].user.id, old_parent_share_id, write=True):
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        # check write permissions on old_datastores
        for old_datastore_id in old_datastores:
            try:
                Data_Store.objects.get(pk=old_datastore_id, user=self.context['request'].user)
            except Data_Store.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        # check if new parent share exists and permissions
        if new_parent_share_id is not None and not user_has_rights_on_share(self.context['request'].user.id,
                                                                            new_parent_share_id, write=True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # check if new_datastore exists
        if new_parent_datastore_id and not Data_Store.objects.filter(pk=new_parent_datastore_id, user=self.context['request'].user).exists():
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['link_id'] = link_id
        attrs['new_parent_share_id'] = new_parent_share_id
        attrs['new_parent_datastore_id'] = new_parent_datastore_id
        attrs['files'] = files

        return attrs