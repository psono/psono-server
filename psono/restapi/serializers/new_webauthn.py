from django.conf import settings
from urllib.parse import urlparse
from rest_framework import serializers, exceptions

class NewWebauthnSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)
    origin = serializers.CharField(max_length=512)

    def validate(self, attrs: dict) -> dict:


        title = attrs.get('title', '').strip()
        origin = attrs.get('origin', '').strip()

        if settings.ALLOWED_SECOND_FACTORS and 'webauthn' not in settings.ALLOWED_SECOND_FACTORS:
            msg = 'SERVER_NOT_SUPPORT_WEBAUTHN'
            raise exceptions.ValidationError(msg)

        allowed_protocols = [
            'https://',
            'chrome-extension://', # chrome, chromium, brave
            'extension://', # edge
        ]
        if not any(origin.startswith(protocol) for protocol in allowed_protocols):
            msg = 'PROTOCOL_NOT_SUPPORTED'
            raise exceptions.ValidationError(msg)

        url = urlparse(origin)

        attrs['title'] = title
        attrs['origin'] = url.scheme + '://' + url.netloc
        attrs['rp_id'] = url.netloc

        return attrs