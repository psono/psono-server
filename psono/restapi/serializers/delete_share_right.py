from ..utils import user_has_rights_on_share

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import User_Share_Right, Group_Share_Right, User_Group_Membership


class DeleteShareRightSerializer(serializers.Serializer):

    user_share_right_id = UUIDField(required=False)
    group_share_right_id = UUIDField(required=False)

    def validate(self, attrs: dict) -> dict:
        user_share_right_id = attrs.get('user_share_right_id', None)
        group_share_right_id = attrs.get('group_share_right_id', None)

        if user_share_right_id is None and group_share_right_id is None:
            msg = _("Either user or group share right needs to be specified.")
            raise exceptions.ValidationError(msg)

        if user_share_right_id is not None and group_share_right_id is not None:
            msg = _("Either user or group share right needs to be specified, not both.")
            raise exceptions.ValidationError(msg)

        if user_share_right_id:
            # check if share_right exists
            try:
                share_right = User_Share_Right.objects.get(pk=user_share_right_id)
            except User_Share_Right.DoesNotExist:
                msg = _("NO_PERMISSION_OR_NOT_EXIST")
                raise exceptions.ValidationError(msg)

            # check if the user has grant rights on this share
            if not user_has_rights_on_share(self.context['request'].user.id, share_right.share_id, grant=True):
                msg = _("NO_PERMISSION_OR_NOT_EXIST")
                raise exceptions.ValidationError(msg)
        else:
            # check if share_right exists
            try:
                share_right = Group_Share_Right.objects.get(pk=group_share_right_id)
            except Group_Share_Right.DoesNotExist:
                msg = _("NO_PERMISSION_OR_NOT_EXIST")
                raise exceptions.ValidationError(msg)

            #check Permissions on group
            try:
                User_Group_Membership.objects.get(group_id=share_right.group_id, user_id=self.context['request'].user.id, share_admin=True)
            except User_Group_Membership.DoesNotExist:
                msg = _('You don\'t have the necessary rights to share with this group.')
                raise exceptions.ValidationError(msg)

        attrs['share_right'] = share_right

        return attrs

