import uuid

from django.utils.http import urlsafe_base64_decode as uid_decoder

from rest_framework import serializers


class ShareOverviewSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    data = serializers.CharField()
    data_nonce = serializers.CharField(max_length=64)
    user = serializers.UUIDField(default=uuid.uuid4)