import uuid
import re

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions


class CreateShareSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    data = serializers.CharField(required=True)
    data_nonce = serializers.CharField(required=True, max_length=64)
    key = serializers.CharField(max_length=256)
    key_nonce = serializers.CharField(max_length=64)

    def validate_data(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('data must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_data_nonce(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('data_nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value