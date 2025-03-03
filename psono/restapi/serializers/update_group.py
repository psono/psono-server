from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import User_Group_Membership

class UpdateGroupSerializer(serializers.Serializer):

    group_id = UUIDField(required=True)
    name = serializers.CharField(max_length=64, required=True)

    def validate(self, attrs: dict) -> dict:

        group_id = attrs.get('group_id')
        name = attrs.get('name')

        if len(name) < 3:
            msg = 'NAME_TOO_SHORT'
            raise exceptions.ValidationError(msg)

        if '@' in name:
            msg = 'NAME_CONTAINS_FORBIDDEN_CHARACTERS'
            raise exceptions.ValidationError(msg)

        # Lets check if the current user can do that
        try:
            membership = User_Group_Membership.objects.select_related('group').get(user=self.context['request'].user, group_id=group_id, group_admin=True, accepted=True)
        except User_Group_Membership.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)


        attrs['group'] = membership.group
        attrs['name'] = name

        return attrs
