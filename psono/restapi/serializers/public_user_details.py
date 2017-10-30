import uuid

from django.utils.http import urlsafe_base64_decode as uid_decoder

from rest_framework import serializers

class PublicUserDetailsSerializer(serializers.Serializer):
    id = serializers.UUIDField(default=uuid.uuid4)