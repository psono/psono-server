try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import User_Group_Membership

class UpdateGroupSerializer(serializers.Serializer):

    group_id = serializers.UUIDField(required=True)
    name = serializers.CharField(max_length=64, required=False)

    def validate(self, attrs):

        group_id = attrs.get('group_id')
        name = attrs.get('name', False)

        # Lets check if the current user can do that
        try:
            membership = User_Group_Membership.objects.select_related('group').get(user=self.context['request'].user, group_id=group_id, group_admin=True, accepted=True)
        except User_Group_Membership.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['group'] = membership.group
        attrs['name'] = name

        return attrs
