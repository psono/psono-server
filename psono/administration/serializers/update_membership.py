from rest_framework import serializers, exceptions
from restapi.fields import UUIDField, BooleanField

from restapi.models import User_Group_Membership

class UpdateMembershipSerializer(serializers.Serializer):
    membership_id = UUIDField(required=True)
    group_admin = BooleanField(required=False, allow_null=True)
    share_admin = BooleanField(required=False, allow_null=True)

    def validate(self, attrs: dict) -> dict:

        membership_id = attrs.get('membership_id')

        try:
            membership = User_Group_Membership.objects.get(id=membership_id)
        except User_Group_Membership.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['membership'] = membership

        return attrs
