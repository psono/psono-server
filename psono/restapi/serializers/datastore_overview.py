import uuid

from rest_framework import serializers
from ..fields import UUIDField, BooleanField

class DatastoreOverviewSerializer(serializers.Serializer):

    id = UUIDField(default=uuid.uuid4)
    type = serializers.CharField(max_length=64, default='password')
    description = serializers.CharField(max_length=64, default='default')
    is_default = BooleanField()