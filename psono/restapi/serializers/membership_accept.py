from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, exceptions
from ..fields import UUIDField

from ..models import User_Group_Membership

class MembershipAcceptSerializer(serializers.Serializer):

    membership_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        membership_id = attrs.get('membership_id')

        try:
            membership_obj = User_Group_Membership.objects.get(pk=membership_id, user=self.context['request'].user, accepted=None)
        except User_Group_Membership.DoesNotExist:
            msg = _("You don't have permission to access it or it does not exist or you already accepted or declined this membership.")
            raise exceptions.ValidationError(msg)

        attrs['membership_obj'] = membership_obj

        return attrs