from ..utils import user_has_rights_on_share
from  more_itertools import unique_everseen

from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Secret_Link, Data_Store


class DeleteSecretLinkSerializer(serializers.Serializer):

    link_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:
        link_id = attrs.get('link_id')

        secrets = []
        parent_shares = []
        parent_datastores = []

        for s in Secret_Link.objects.filter(link_id=link_id).all():
            secrets.append(s.secret_id)
            if s.parent_share_id:
                parent_shares.append(s.parent_share_id)
            if s.parent_datastore_id:
                parent_datastores.append(s.parent_datastore_id)

        # remove duplicates
        secrets = list(unique_everseen(secrets))
        parent_shares = list(unique_everseen(parent_shares))
        parent_datastores = list(unique_everseen(parent_datastores))


        if not secrets and not parent_shares and not parent_datastores:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # check write permissions on parent_shares
        for parent_share_id in parent_shares:
            if not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        # check write permissions on parent_datastores
        for datastore_id in parent_datastores:
            if not Data_Store.objects.filter(pk=datastore_id, user=self.context['request'].user).exists():
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        attrs['link_id'] = link_id

        return attrs

