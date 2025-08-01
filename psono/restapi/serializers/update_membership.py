from rest_framework import serializers, exceptions
from ..fields import UUIDField, BooleanField
from ..models import User_Group_Membership

class UpdateMembershipSerializer(serializers.Serializer):

    membership_id = UUIDField(required=True)
    group_admin = BooleanField(default=False)
    share_admin = BooleanField(default=True)

    def validate(self, attrs: dict) -> dict:

        membership_id = attrs.get('membership_id')

        # Lets check if the membership exists
        try:
            membership = User_Group_Membership.objects.get(pk=membership_id)
        except User_Group_Membership.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        # Lets check if the current user can do that
        if not User_Group_Membership.objects.filter(user=self.context['request'].user, group=membership.group, group_admin=True, accepted=True).exists():
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['membership'] = membership

        return attrs
