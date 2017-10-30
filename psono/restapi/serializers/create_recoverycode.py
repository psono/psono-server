import re

from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions



class CreateRecoverycodeSerializer(serializers.Serializer):

    recovery_authkey = serializers.CharField(required=True)
    recovery_data = serializers.CharField(required=True)
    recovery_data_nonce = serializers.CharField(max_length=64, required=True)
    recovery_sauce = serializers.CharField(max_length=64, required=True)


    def validate_recovery_data(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Recovery data must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_recovery_data_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Recovery data nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value