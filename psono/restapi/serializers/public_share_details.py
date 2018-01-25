import uuid

from rest_framework import serializers



class PublicShareDetailsSerializer(serializers.Serializer):
    id = serializers.UUIDField(default=uuid.uuid4)