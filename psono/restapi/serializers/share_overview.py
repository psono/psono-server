import uuid

from rest_framework import serializers
from ..fields import UUIDField


class ShareOverviewSerializer(serializers.Serializer):

    id = UUIDField(default=uuid.uuid4)
    data = serializers.CharField()
    data_nonce = serializers.CharField(max_length=64)
    user = UUIDField(default=uuid.uuid4)