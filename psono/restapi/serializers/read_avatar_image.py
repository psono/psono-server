from rest_framework import serializers, exceptions
from ..models import Avatar
from ..utils.avatar import get_avatar_storage

class ReadAvatarImageSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        avatar_id = self.context['request'].parser_context['kwargs'].get('avatar_id', False)
        user_id = self.context['request'].parser_context['kwargs'].get('user_id', False)

        try:
            avatar = Avatar.objects.get(pk=avatar_id, user_id=user_id)
        except Avatar.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        storage = get_avatar_storage()
        data = None
        if storage:
            try:
                with storage.open(f"{settings.AVATAR_STORAGE_PREFIX}{user_id}/{avatar.id}".lower(), 'rb') as file:
                    data = file.read()
            except FileNotFoundError:
                pass
        if not data:
            data = avatar.data

        if not data:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['mime_type'] = avatar.mime_type
        attrs['data'] = avatar.data

        return attrs