from ..utils import user_has_rights_on_share

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import User, Group, User_Share_Right, Group_Share_Right


class CreateShareRightSerializer(serializers.Serializer):
    key = serializers.CharField(max_length=256, required=False)
    key_nonce = serializers.CharField(max_length=64, required=False)
    title = serializers.CharField(max_length=512, required=False)
    title_nonce = serializers.CharField(max_length=64, required=False)
    type = serializers.CharField(max_length=512, required=False)
    type_nonce = serializers.CharField(max_length=64, required=False)
    share_id = serializers.UUIDField(required=True)
    user_id = serializers.UUIDField(required=False)
    group_id = serializers.UUIDField(required=False)
    read = serializers.BooleanField()
    write = serializers.BooleanField()
    grant = serializers.BooleanField()

    def validate(self, attrs):

        user_id = attrs.get('user_id', False)
        group_id = attrs.get('group_id', False)
        share_id = attrs['share_id']

        if not user_id and not group_id:
            msg = _("Either user or group share right needs to be specified.")
            raise exceptions.ValidationError(msg)

        if user_id and group_id:
            msg = _("Either user or group share right needs to be specified, not both.")
            raise exceptions.ValidationError(msg)

        # check permissions on share
        if not user_has_rights_on_share(self.context['request'].user.id, share_id, grant=True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        if user_id:
            # check if user exists
            try:
                attrs['user'] = User.objects.get(pk=attrs['user_id'])
            except User.DoesNotExist:
                msg = _('Target user does not exist.')
                raise exceptions.ValidationError(msg)

            # Lets see if it the share right already exists
            try:
                User_Share_Right.objects.get(share_id=share_id, user_id=user_id)
                msg = _("User Share Right already exists.")
                raise exceptions.ValidationError(msg)
            except User_Share_Right.DoesNotExist:
                pass # Good it doesn't exist yet

        # check if group exists
        if group_id:
            try:
                attrs['group'] = Group.objects.get(pk=attrs['group_id'])
            except Group.DoesNotExist:
                msg = _('Target group does not exist.')
                raise exceptions.ValidationError(msg)

            try:
                # Lets see if it the share right already exists
                Group_Share_Right.objects.get(share_id=share_id, group_id=group_id)
                msg = _("Group Share Right already exists.")
                raise exceptions.ValidationError(msg)
            except Group_Share_Right.DoesNotExist:
                pass # Good it doesn't exist yet

        return attrs