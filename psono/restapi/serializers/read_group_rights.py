from rest_framework import serializers, exceptions
from django.utils.translation import gettext_lazy as _

from ..models import User_Group_Membership

class ReadGroupRightsSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        group_id = self.context['request'].parser_context['kwargs'].get('group_id', False)

        if group_id:
            # Lets check if the current user can do that
            if not User_Group_Membership.objects.filter(user=self.context['request'].user, group_id=group_id, accepted=True).exists():
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)
        attrs['group_id'] = group_id
        return attrs