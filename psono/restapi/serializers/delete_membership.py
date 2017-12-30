from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import User_Group_Membership

class DeleteMembershipSerializer(serializers.Serializer):

    membership_id = serializers.UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        membership_id = attrs.get('membership_id')

        try:
            membership = User_Group_Membership.objects.get(pk=membership_id)
        except User_Group_Membership.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        if membership.user != self.context['request'].user:
            # Its not his own membership right (leave group functionality) check if the user has the necessary access
            # privileges for this group
            try:
                User_Group_Membership.objects.get(group_id=membership.group_id, user=self.context['request'].user,
                                                  group_admin=True, accepted=True)

            except User_Group_Membership.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        attrs['membership'] = membership

        return attrs