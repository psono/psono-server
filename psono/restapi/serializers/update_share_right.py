from ..utils import user_has_rights_on_share

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField, BooleanField
from ..models import User_Share_Right, Group_Share_Right


class UpdateShareRightSerializer(serializers.Serializer):
    share_id = UUIDField(required=True)
    user_id = UUIDField(required=False)
    group_id = UUIDField(required=False)
    read = BooleanField()
    write = BooleanField()
    grant = BooleanField()

    def validate(self, attrs: dict) -> dict:

        user_id = attrs.get('user_id', False)
        group_id = attrs.get('group_id', False)

        share_id = attrs['share_id']

        if not user_id and not group_id:
            msg = _("Either user id or group id needs to be specified.")
            raise exceptions.ValidationError(msg)

        if user_id and group_id:
            msg = _("Either user id or group id needs to be specified, not both.")
            raise exceptions.ValidationError(msg)

        # check permissions on share
        if not user_has_rights_on_share(self.context['request'].user.id, share_id, grant=True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        share_right_obj = None

        if user_id:
            try:
                share_right_obj = User_Share_Right.objects.get(share_id=share_id, user_id=user_id)
            except User_Share_Right.DoesNotExist:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        if group_id:
            try:
                share_right_obj = Group_Share_Right.objects.get(share_id=share_id, group_id=group_id)
            except Group_Share_Right.DoesNotExist:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        attrs['share_right_obj'] = share_right_obj

        return attrs