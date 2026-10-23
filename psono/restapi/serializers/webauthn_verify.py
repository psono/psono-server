import json

from django.db import transaction
from django.utils import timezone
from rest_framework import serializers, exceptions
import nacl.encoding
from webauthn import verify_authentication_response
from webauthn import base64url_to_bytes
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from ..models import Webauthn
from ..utils import (
    authentication_webauthn_origins,
    effective_webauthn_rp_id,
    encrypt_webauthn_challenges,
    get_webauthn_challenges,
)


class WebauthnVerifySerializer(serializers.Serializer):
    credential = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        credential = attrs.get("credential", "").strip()

        token = self.context["request"].auth
        parsed_credential = json.loads(credential)

        credential_id = nacl.encoding.HexEncoder.encode(
            base64url_to_bytes(parsed_credential["rawId"])
        ).decode()

        with transaction.atomic():
            # Consistent lock ordering serializes initialization/consumption
            # across credentials without deadlocking concurrent login attempts.
            webauthns = list(
                Webauthn.objects.select_for_update()
                .filter(user=self.context["request"].user, active=True)
                .order_by("id")
            )
            matches = [w for w in webauthns if w.credential_id == credential_id]
            if len(matches) != 1:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)
            webauthn = matches[0]
            now = timezone.now()
            token_id = str(token.id)
            sessions = get_webauthn_challenges(webauthn, now)
            context = sessions.get(token_id)
            if context is None:
                msg = "NO_PERMISSION_OR_NOT_EXIST"
                raise exceptions.ValidationError(msg)
            challenge = context["challenge"]
            # Consume this token's attempt across all candidate credentials,
            # while preserving other sessions and their original expiry times.
            for w in webauthns:
                sessions = get_webauthn_challenges(w, now)
                if token_id in sessions:
                    del sessions[token_id]
                    w.challenge = encrypt_webauthn_challenges(sessions)
                    Webauthn.objects.filter(pk=w.pk).update(challenge=w.challenge)

        try:
            verify_authentication_response(
                credential=credential,
                expected_challenge=challenge.encode(),
                expected_rp_id=effective_webauthn_rp_id(webauthn),
                expected_origin=authentication_webauthn_origins(webauthn),
                credential_public_key=nacl.encoding.HexEncoder.decode(
                    webauthn.credential_public_key
                ),
                credential_current_sign_count=0,
                require_user_verification=False,
            )
        except InvalidAuthenticationResponse:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs["token"] = token
        return attrs
