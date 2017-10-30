import re

from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions


class SetNewPasswordSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'Enter a valid username' })
    recovery_authkey = serializers.CharField(required=True)
    update_data = serializers.CharField(required=True)
    update_data_nonce = serializers.CharField(max_length=64, required=True)



    def validate_update_data(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Update data must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value


    def validate_update_data_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Update data nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value