try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from rest_framework import serializers, exceptions

from ..models import User_Group_Membership

class ReadGroupRightsSerializer(serializers.Serializer):
    uuid = serializers.UUIDField(required=False)

    def validate(self, attrs):
        uuid = attrs.get('uuid', None)

        if uuid is not None:
            # Lets check if the current user can do that
            try:
                User_Group_Membership.objects.get(user=self.context['request'].user, group_id=uuid, accepted=True)
            except User_Group_Membership.DoesNotExist:
                msg = _("You don't have permission to access or it does not exist.")
                raise exceptions.ValidationError(msg)

        return attrs