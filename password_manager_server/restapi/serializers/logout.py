from ..authentication import TokenAuthentication

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from rest_framework import serializers

class LogoutSerializer(serializers.Serializer):
    token = serializers.CharField(required=False)
    session_id = serializers.CharField(required=False)

    def validate(self, attrs):

        attrs['token_hash'] = TokenAuthentication.get_token_hash(self.context['request'])

        return attrs