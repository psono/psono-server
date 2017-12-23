from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import User_Group_Membership, Group

class DeleteGroupSerializer(serializers.Serializer):

    group_id = serializers.UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        group_id = attrs.get('group_id')

        # check if the group exists
        try:
            group = Group.objects.only('id').get(pk=group_id, members__user=self.context['request'].user, members__group_admin=True, members__accepted=True)
        except Group.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        attrs['group'] = group

        return attrs

