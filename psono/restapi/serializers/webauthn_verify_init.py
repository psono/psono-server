from urllib.parse import urlparse
from rest_framework import serializers, exceptions

from ..models import Webauthn
from ..utils import shared_webauthn_scope, webauthn_origin


class WebauthnVerifyInitSerializer(serializers.Serializer):
    origin = serializers.CharField(max_length=512)
    rp_id = serializers.CharField(max_length=253, required=False)
    legacy = serializers.BooleanField(default=False)

    def validate(self, attrs: dict) -> dict:

        origin = attrs.get("origin", "").strip()

        allowed_protocols = [
            "https://",
            "chrome-extension://",  # chrome, chromium, brave
            "extension://",  # edge
            "moz-extension://",  # Firefox 150+
        ]
        if not any(origin.startswith(protocol) for protocol in allowed_protocols):
            msg = "PROTOCOL_NOT_SUPPORTED"
            raise exceptions.ValidationError(msg)

        url = urlparse(origin)

        try:
            origin = webauthn_origin(origin)
        except ValueError:
            raise exceptions.ValidationError({"origin": "INVALID_ORIGIN"})
        candidates = Webauthn.objects.filter(
            user_id=self.context["request"].user.id,
            active=True,
        )
        shared_rp_id, trusted_origins = shared_webauthn_scope()
        requested_rp_id = attrs.get("rp_id")
        chromium_extension = url.scheme in ("chrome-extension", "extension")
        legacy_webauthns = candidates.filter(origin=origin, rp_id=url.netloc)
        shared = (
            origin in trusted_origins
            and not attrs["legacy"]
            and (requested_rp_id is not None or url.scheme == "https")
        )
        if shared and requested_rp_id not in (None, shared_rp_id):
            raise exceptions.ValidationError({"rp_id": "RP_ID_NOT_ALLOWED"})

        rp_id = url.netloc
        if shared:
            rp_id = shared_rp_id
            webauthns = candidates.filter(
                origin__in=trusted_origins, rp_id=shared_rp_id
            )
            # A new client can still log in when it only has old extension keys.
            if chromium_extension and not webauthns.exists():
                shared = False
                rp_id = url.netloc
                webauthns = legacy_webauthns
        elif chromium_extension:
            webauthns = legacy_webauthns
        else:
            # Preserve access to existing isolated registrations, including
            # Firefox credentials from custom extensions outside the trust group.
            rp_id = requested_rp_id or url.netloc
            webauthns = candidates.filter(origin=origin, rp_id=rp_id)
        if not webauthns.exists():
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["origin"] = origin
        attrs["rp_id"] = rp_id
        attrs["webauthns"] = webauthns
        attrs["legacy_available"] = (
            shared and chromium_extension and legacy_webauthns.exists()
        )

        return attrs
