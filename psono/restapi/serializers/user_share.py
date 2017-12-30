import uuid

from rest_framework import serializers
from . import PublicUserDetailsSerializer # type: ignore



class UserShareSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    key = serializers.CharField(max_length=256)
    key_nonce = serializers.CharField(max_length=64)
    title = serializers.CharField(max_length=256)
    read = serializers.BooleanField()
    write = serializers.BooleanField()
    grant = serializers.BooleanField()

    user = PublicUserDetailsSerializer()