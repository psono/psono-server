import uuid

from rest_framework import serializers
from ..fields import UUIDField, BooleanField
from . import PublicUserDetailsSerializer # type: ignore



class UserShareSerializer(serializers.Serializer):

    id = UUIDField(default=uuid.uuid4)
    key = serializers.CharField(max_length=256)
    key_nonce = serializers.CharField(max_length=64)
    title = serializers.CharField(max_length=256)
    read = BooleanField()
    write = BooleanField()
    grant = BooleanField()

    user = PublicUserDetailsSerializer()