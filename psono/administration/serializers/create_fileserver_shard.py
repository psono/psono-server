from rest_framework import serializers
from restapi.fields import BooleanField


class CreateFileserverShardSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256, required=True, trim_whitespace=True)
    description = serializers.CharField(required=True, allow_blank=True)
    active = BooleanField(required=False, default=True)
