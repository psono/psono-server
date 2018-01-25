from rest_framework import serializers

class NewGASerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)
