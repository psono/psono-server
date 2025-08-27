
from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import User_Group_Membership

class DeleteMembershipSerializer(serializers.Serializer):

    membership_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        membership_id = attrs.get('membership_id')

        try:
            membership = User_Group_Membership.objects.get(pk=membership_id)
        except User_Group_Membership.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if membership.user != self.context['request'].user:
            # Its not his own membership right (leave group functionality) check if the user has the necessary access
            # privileges for this group
            if not User_Group_Membership.objects.filter(group_id=membership.group_id, user=self.context['request'].user,
                                                        group_admin=True, accepted=True).exists():
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

        attrs['membership'] = membership

        return attrs