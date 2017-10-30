import uuid

from django.utils.http import urlsafe_base64_decode as uid_decoder


from rest_framework import serializers


class CreateDatastoreSerializer(serializers.Serializer):

    type = serializers.CharField(max_length=64, required=True)
    description = serializers.CharField(max_length=64, required=True)
    data = serializers.CharField(required=False, allow_blank=True)
    data_nonce = serializers.CharField(required=False, allow_blank=True, max_length=64)
    secret_key = serializers.CharField(max_length=256)
    secret_key_nonce = serializers.CharField(max_length=64)
    is_default = serializers.BooleanField(required=False, default=True)