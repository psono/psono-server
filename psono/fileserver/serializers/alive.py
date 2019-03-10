from rest_framework import serializers


class FileserverAliveSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        return attrs
