from rest_framework import serializers, exceptions
from ..models import Avatar
from ..models import User

class ReadAvatarSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        avatar_id = self.context['request'].parser_context['kwargs'].get('avatar_id', False)
        user_id = self.context['request'].parser_context['kwargs'].get('user_id', False)


        if avatar_id:
            try:
                avatar = Avatar.objects.get(pk=avatar_id)
            except Avatar.DoesNotExist:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)

            attrs['avatar'] = avatar

        if user_id:
            if user_id.lower() != str(self.context['request'].user.id).lower():
                try:
                    user = User.objects.get(pk=user_id)
                except User.DoesNotExist:
                    msg = "NO_PERMISSION_OR_NOT_EXIST"
                    raise exceptions.ValidationError(msg)
            else:
                user = self.context['request'].user

            attrs['user'] = user

        return attrs