from rest_framework import serializers


class CreateFileserverClusterSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256, required=True, trim_whitespace=True)
    file_size_limit = serializers.IntegerField(
        required=False, default=0, min_value=0, max_value=9223372036854775807
    )
