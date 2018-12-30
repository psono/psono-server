from rest_framework import serializers


class AuthorizeDownloadSerializer(serializers.Serializer):

    def validate(self, attrs: dict) -> dict:

        return attrs
