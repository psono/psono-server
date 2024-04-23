from rest_framework import serializers, exceptions
from ..fields import UUIDField
from ..models import Avatar

class DeleteAvatarSerializer(serializers.Serializer):
    avatar_id = UUIDField(required=True)

    def validate(self, attrs: dict) -> dict:

        avatar_id = attrs.get('avatar_id')

        try:
            avatar = Avatar.objects.get(pk=avatar_id, user=self.context['request'].user)
        except Avatar.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['avatar'] = avatar

        return attrs