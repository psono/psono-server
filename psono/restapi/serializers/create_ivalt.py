from rest_framework import serializers


class CreateIvaltSerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length=256, required=True)
