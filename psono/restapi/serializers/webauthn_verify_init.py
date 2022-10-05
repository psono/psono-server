from urllib.parse import urlparse
from rest_framework import serializers, exceptions

from ..models import Webauthn

class WebauthnVerifyInitSerializer(serializers.Serializer):
    origin = serializers.CharField(max_length=512)

    def validate(self, attrs: dict) -> dict:

        origin = attrs.get('origin', '').strip()

        allowed_protocols = [
            'https://',
            'chrome-extension://', # chrome, chromium, brave
            'extension://', # edge
        ]
        if not any(origin.startswith(protocol) for protocol in allowed_protocols):
            msg = 'PROTOCOL_NOT_SUPPORTED'
            raise exceptions.ValidationError(msg)

        url = urlparse(origin)

        if not Webauthn.objects.filter(user_id=self.context['request'].user.id, origin=url.scheme + '://' + url.netloc, active=True).exists():
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['origin'] = url.scheme + '://' + url.netloc
        attrs['rp_id'] = url.netloc

        return attrs
