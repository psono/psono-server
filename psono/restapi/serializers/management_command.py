from rest_framework import serializers
from rest_framework import exceptions
from django.conf import settings

class ManagementCommandSerializer(serializers.Serializer):
    command_name = serializers.CharField(required=True)
    command_args = serializers.ListField(required=False, default=[])

    def validate(self, attrs: dict) -> dict:

        command_name = attrs.get('command_name', '').strip()

        attrs['command_name'] = command_name

        if command_name not in settings.MANAGEMENT_COMMANDS:
            msg = 'MANAGEMENT_COMMAND_NOT_ALLOWED'
            raise exceptions.ValidationError(msg)

        return attrs
