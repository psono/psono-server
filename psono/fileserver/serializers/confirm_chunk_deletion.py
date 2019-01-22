from rest_framework import serializers


class FileserverConfirmChunkDeletionSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:
        return attrs
