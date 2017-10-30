import uuid

from django.utils.http import urlsafe_base64_decode as uid_decoder

from rest_framework import serializers

class DatastoreOverviewSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    type = serializers.CharField(max_length=64, default='password')
    description = serializers.CharField(max_length=64, default='default')
    is_default = serializers.BooleanField()