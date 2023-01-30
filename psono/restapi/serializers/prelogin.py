from ..models import User

from rest_framework import serializers


class PreLoginSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={'invalid': 'INVALID_USERNAME_FORMAT'})

    def validate(self, attrs: dict) -> dict:

        username = attrs.get('username')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        attrs['user'] = user

        return attrs
