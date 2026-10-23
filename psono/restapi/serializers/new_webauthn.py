from django.conf import settings
from urllib.parse import urlparse
from rest_framework import serializers, exceptions

from ..utils import shared_webauthn_scope, webauthn_origin


class NewWebauthnSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)
    origin = serializers.CharField(max_length=512)
    rp_id = serializers.RegexField(
        r"\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z", max_length=253, required=False
    )

    def validate(self, attrs: dict) -> dict:

        title = attrs.get("title", "").strip()
        origin = attrs.get("origin", "").strip()

        if (
            settings.ALLOWED_SECOND_FACTORS
            and "webauthn" not in settings.ALLOWED_SECOND_FACTORS
        ):
            msg = "SERVER_NOT_SUPPORT_WEBAUTHN"
            raise exceptions.ValidationError(msg)

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

        attrs["title"] = title
        try:
            attrs["origin"] = webauthn_origin(origin)
        except ValueError:
            raise exceptions.ValidationError({"origin": "INVALID_ORIGIN"})
        shared_rp_id, trusted_origins = shared_webauthn_scope()
        requested_rp_id = attrs.get("rp_id")
        if requested_rp_id:
            if (
                attrs["origin"] not in trusted_origins
                or requested_rp_id != shared_rp_id
            ):
                raise exceptions.ValidationError({"rp_id": "RP_ID_NOT_ALLOWED"})
            attrs["rp_id"] = shared_rp_id
        elif url.scheme == "moz-extension":
            raise exceptions.ValidationError({"rp_id": "This field is required."})
        elif url.scheme == "https" and attrs["origin"] in trusted_origins:
            attrs["rp_id"] = shared_rp_id
        else:
            # Older extension clients omit rp_id and create extension-scoped keys.
            attrs["rp_id"] = url.netloc

        return attrs
