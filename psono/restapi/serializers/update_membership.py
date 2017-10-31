from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import User_Group_Membership

class UpdateMembershipSerializer(serializers.Serializer):

    membership_id = serializers.UUIDField(required=True)
    group_admin = serializers.BooleanField(default=False)

    def validate(self, attrs):

        membership_id = attrs.get('membership_id')

        # Lets check if the membership exists
        try:
            membership = User_Group_Membership.objects.get(pk=membership_id)
        except User_Group_Membership.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # Lets check if the current user can do that
        try:
            User_Group_Membership.objects.get(user=self.context['request'].user, group=membership.group, group_admin=True, accepted=True)
        except User_Group_Membership.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['membership'] = membership

        return attrs
