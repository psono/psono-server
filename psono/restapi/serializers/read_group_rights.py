from django.utils.http import urlsafe_base64_decode as uid_decoder

from rest_framework import serializers, exceptions
from django.utils.translation import ugettext_lazy as _

from ..models import User_Group_Membership

class ReadGroupRightsSerializer(serializers.Serializer):

    def validate(self, attrs):
        group_id = self.context['request'].parser_context['kwargs'].get('group_id', False)

        if group_id:
            # Lets check if the current user can do that
            try:
                User_Group_Membership.objects.get(user=self.context['request'].user, group_id=group_id, accepted=True)
            except User_Group_Membership.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)
        attrs['group_id'] = group_id
        return attrs