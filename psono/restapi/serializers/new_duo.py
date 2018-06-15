from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions

from ..utils import duo_auth_check, duo_auth_enroll
from ..models import Duo

class NewDuoSerializer(serializers.Serializer):

    title = serializers.CharField(max_length=256, required=True)
    integration_key = serializers.CharField(max_length=32, required=True)
    secret_key = serializers.CharField(max_length=128, required=True)
    host = serializers.CharField(max_length=32, required=True)


    def validate(self, attrs: dict) -> dict:

        title = attrs.get('title', '').strip()
        integration_key = attrs.get('integration_key', '').strip()
        secret_key = attrs.get('secret_key', '').strip()
        host = attrs.get('host', '').strip()

        if Duo.objects.filter(user=self.context['request'].user).count() > 0:
            msg = _('Only one Duo device allowed.')
            raise exceptions.ValidationError(msg)

        if settings.ALLOWED_SECOND_FACTORS and 'duo' not in settings.ALLOWED_SECOND_FACTORS:
            msg = _('The server does not allow Duo 2FA.')
            raise exceptions.ValidationError(msg)


        check = duo_auth_check(integration_key, secret_key, host)

        if "error" in check:
            msg = _(check['error'])
            raise exceptions.ValidationError(msg)

        username, domain = self.context['request'].user.username.split("@")
        enrollment = duo_auth_enroll(integration_key, secret_key, host, username)

        if "error" in enrollment:
            msg = _(enrollment['error'])
            raise exceptions.ValidationError(msg)

        validity_in_seconds = enrollment['expiration'] - check['time']

        attrs['title'] = title
        attrs['integration_key'] = integration_key
        attrs['secret_key'] = secret_key
        attrs['host'] = host
        attrs['enrollment_user_id'] = enrollment['user_id']
        attrs['enrollment_activation_code'] = enrollment['activation_code']
        attrs['validity_in_seconds'] = validity_in_seconds

        return attrs