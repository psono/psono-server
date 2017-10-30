from django.utils.http import urlsafe_base64_decode as uid_decoder
from rest_framework import serializers

class NewGASerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)
