from rest_framework import serializers


class AuthorizeUploadSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:

        return attrs
