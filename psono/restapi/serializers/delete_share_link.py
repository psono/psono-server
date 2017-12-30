from ..utils import user_has_rights_on_share
from  more_itertools import unique_everseen

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import Data_Store, Share_Tree

class DeleteShareLinkSerializer(serializers.Serializer):

    link_id = serializers.UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        link_id = str(attrs.get('link_id')).replace("-", "")

        shares = []
        parents = []
        datastores = []

        for s in Share_Tree.objects.filter(path__match='*.' + link_id).all():
            shares.append(s.share_id)
            if s.parent_share_id:
                parents.append(s.parent_share_id)
            if s.parent_datastore_id:
                datastores.append(s.parent_datastore_id)

        # remove duplicates
        shares = list(unique_everseen(shares))
        parents = list(unique_everseen(parents))
        datastores = list(unique_everseen(datastores))


        if not shares and not parents and not datastores:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # check write permissions on parents
        for parent_share_id in parents:
            if not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        # check write permissions on datastores
        for datastore_id in datastores:
            try:
                Data_Store.objects.get(pk=datastore_id, user=self.context['request'].user)
            except Data_Store.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        return attrs

