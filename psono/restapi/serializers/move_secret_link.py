from ..utils import user_has_rights_on_share
from  more_itertools import unique_everseen


from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Secret_Link, Data_Store


class MoveSecretLinkSerializer(serializers.Serializer):

    link_id = UUIDField(required=True)
    new_parent_share_id = UUIDField(required=False)
    new_parent_datastore_id = UUIDField(required=False)

    def validate(self, attrs: dict) -> dict:
        link_id = attrs.get('link_id')
        new_parent_share_id = attrs.get('new_parent_share_id', None)
        new_parent_datastore_id = attrs.get('new_parent_datastore_id', None)

        if new_parent_share_id is None and new_parent_datastore_id is None:
            msg = "NO_PARENT_PROVIDED"
            raise exceptions.ValidationError(msg)

        secrets = []
        old_parents = []
        old_datastores = []

        for s in Secret_Link.objects.filter(link_id=link_id).all():
            secrets.append(s.secret_id)
            if s.parent_share_id:
                old_parents.append(s.parent_share_id)
            if s.parent_datastore_id:
                old_datastores.append(s.parent_datastore_id)

        # remove duplicates
        secrets = list(unique_everseen(secrets))
        old_parents = list(unique_everseen(old_parents))
        old_datastores = list(unique_everseen(old_datastores))

        if not secrets and not old_parents and not old_datastores:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check write permissions on old_parents
        for old_parent_share_id in old_parents:
            if not user_has_rights_on_share(self.context['request'].user.id, old_parent_share_id, write=True):
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        # check write permissions on old_datastores
        for old_datastore_id in old_datastores:
            try:
                Data_Store.objects.get(pk=old_datastore_id, user=self.context['request'].user)
            except Data_Store.DoesNotExist:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        # check if new parent share exists and permissions
        if new_parent_share_id is not None and not user_has_rights_on_share(self.context['request'].user.id,
                                                                            new_parent_share_id, write=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check if new_datastore exists
        if new_parent_datastore_id and not Data_Store.objects.filter(pk=new_parent_datastore_id, user=self.context['request'].user).exists():
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['link_id'] = link_id
        attrs['new_parent_share_id'] = new_parent_share_id
        attrs['new_parent_datastore_id'] = new_parent_datastore_id
        attrs['secrets'] = secrets

        return attrs