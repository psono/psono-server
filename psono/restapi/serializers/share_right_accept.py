from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions

from ..utils import user_has_rights_on_share, get_datastore
from ..models import User_Share_Right

class ShareRightAcceptSerializer(serializers.Serializer):

    share_right_id = serializers.UUIDField(required=True)
    link_id = serializers.UUIDField(required=False) # Deprecated
    parent_share_id = serializers.UUIDField(required=False) # Deprecated
    parent_datastore_id = serializers.UUIDField(required=False) # Deprecated
    key = serializers.CharField(max_length=256, required=False)
    key_type = serializers.CharField(max_length=256, required=False, default='symmetric')
    key_nonce = serializers.CharField(max_length=64, required=False)

    def validate(self, attrs):
        link_id = attrs.get('link_id', None)
        parent_share_id = attrs.get('parent_share_id', None)
        parent_datastore_id = attrs.get('parent_datastore_id', None)
        share_right_id = attrs.get('share_right_id')

        if link_id is not None and (parent_share_id is None and parent_datastore_id is None):
            msg = _("Either parent share or datastore need to be specified.")
            raise exceptions.ValidationError(msg)

        if parent_share_id and parent_datastore_id:
            msg = _("Only one parent can exist, either a datastore or a share.")
            raise exceptions.ValidationError(msg)

        # Check existence and rights:
        if parent_share_id:
            if not user_has_rights_on_share(self.context['request'].user.id, parent_share_id, write=True):
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        if parent_datastore_id:
            parent_datastore = get_datastore(parent_datastore_id, self.context['request'].user)
            if not parent_datastore:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        try:
            user_share_right_obj = User_Share_Right.objects.get(pk=share_right_id, user=self.context['request'].user, accepted=None)
        except User_Share_Right.DoesNotExist:
            msg = _("You don't have permission to access it or it does not exist or you already accepted or declined this share.")
            raise exceptions.ValidationError(msg)

        # Dont add a share without the grant right to a parent share
        if parent_share_id and not user_share_right_obj.grant:
            msg = _("You don't have permission to access it or it does not exist or you already accepted or declined this share.")
            raise exceptions.ValidationError(msg)

        attrs['parent_share_id'] = parent_share_id
        attrs['parent_datastore_id'] = parent_datastore_id
        attrs['user_share_right_obj'] = user_share_right_obj

        return attrs