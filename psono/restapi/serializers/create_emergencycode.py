import re

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions



class CreateEmergencycodeSerializer(serializers.Serializer):

    description = serializers.CharField(required=True)
    activation_delay = serializers.IntegerField(required=True)
    emergency_authkey = serializers.CharField(required=True)
    emergency_data = serializers.CharField(required=True)
    emergency_data_nonce = serializers.CharField(max_length=64, required=True)
    emergency_sauce = serializers.CharField(max_length=64, required=True)


    def validate_emergency_data(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Emergency data must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_emergency_data_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Emergency data nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value


    def validate_activation_delay(self, value):

        if value < 0:
            msg = _('Activation delay needs to be a positive integer')
            raise exceptions.ValidationError(msg)

        return value