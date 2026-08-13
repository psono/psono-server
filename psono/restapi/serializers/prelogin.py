from ..models import User

from rest_framework import serializers


class PreLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, max_length=254)

    def validate_username(self, value: str) -> str:
        username_parts = value.split("@")
        if len(username_parts) != 2 or not all(username_parts):
            raise serializers.ValidationError("INVALID_USERNAME_FORMAT")
        return value

    def validate(self, attrs: dict) -> dict:

        username = attrs.get("username")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        attrs["user"] = user

        return attrs
