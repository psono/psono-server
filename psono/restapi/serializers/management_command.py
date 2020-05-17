from rest_framework import serializers, exceptions

class ManagementCommandSerializer(serializers.Serializer):
    command_name = serializers.CharField(required=True)
    command_args = serializers.ListField(required=False, default=[])

    def validate(self, attrs: dict) -> dict:

        command_name = attrs.get('command_name', '').strip()

        attrs['command_name'] = command_name

        return attrs
