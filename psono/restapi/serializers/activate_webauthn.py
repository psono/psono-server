from rest_framework import serializers, exceptions
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from webauthn import verify_registration_response
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import (
    RegistrationCredential,
)

from ..fields import UUIDField
from ..models import Webauthn
from ..utils import decrypt_with_db_secret, effective_webauthn_rp_id


class ActivateWebauthnSerializer(serializers.Serializer):
    webauthn_id = UUIDField(required=True)
    credential = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        webauthn_id = attrs.get("webauthn_id", "")
        credential = attrs.get("credential", "").strip()

        try:
            webauthn = Webauthn.objects.get(
                pk=webauthn_id, user=self.context["request"].user, active=False
            )
        except Webauthn.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        now = timezone.now()
        cutoff = now - timedelta(seconds=settings.WEBAUTHN_CHALLENGE_TIME_VALID)
        if not cutoff < webauthn.create_date <= now:
            raise exceptions.ValidationError("NO_PERMISSION_OR_NOT_EXIST")

        try:
            registration_verification = verify_registration_response(
                credential=credential,
                expected_challenge=decrypt_with_db_secret(webauthn.challenge).encode(),
                # Registration must finish in the client that initiated it.
                expected_origin=webauthn.origin,
                expected_rp_id=effective_webauthn_rp_id(webauthn),
            )
        except InvalidRegistrationResponse:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["webauthn"] = webauthn
        attrs["credential_id"] = registration_verification.credential_id
        attrs["credential_public_key"] = registration_verification.credential_public_key

        return attrs
