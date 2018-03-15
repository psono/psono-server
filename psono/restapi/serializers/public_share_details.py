import uuid

from rest_framework import serializers
from ..fields import UUIDField



class PublicShareDetailsSerializer(serializers.Serializer):
    id = UUIDField(default=uuid.uuid4)