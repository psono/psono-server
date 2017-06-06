from ..utils import authenticate

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions


class LoginSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'Enter a valid username' })
    authkey = serializers.CharField(style={'input_type': 'password'},  required=True)
    public_key = serializers.CharField(required=True, min_length=64, max_length=64)

    # Not required at the moment to not break backward compatibility but should be set to required in a later version
    device_fingerprint = serializers.CharField(required=False)
    device_description = serializers.CharField(required=False)

    def validate(self, attrs):
        username = attrs.get('username').lower().strip()
        authkey = attrs.get('authkey')
        public_key = attrs.get('public_key')

        user = authenticate(username=username, authkey=authkey)

        if not user:
            msg = _('Username or password wrong.')
            raise exceptions.ValidationError(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.ValidationError(msg)

        if not user.is_email_active:
            msg = _('E-mail is not yet verified.')
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        attrs['user_session_public_key'] = public_key
        return attrs
