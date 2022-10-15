from rest_framework import serializers, exceptions
from webauthn import verify_registration_response
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import (
    RegistrationCredential,
)

from ..fields import UUIDField
from ..models import Webauthn
from ..utils import decrypt_with_db_secret

class ActivateWebauthnSerializer(serializers.Serializer):
    webauthn_id = UUIDField(required=True)
    credential = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        webauthn_id = attrs.get('webauthn_id', '')
        credential = attrs.get('credential', '').strip()

        try:
            webauthn = Webauthn.objects.get(pk=webauthn_id, user=self.context['request'].user, active=False)
        except Webauthn.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if webauthn.origin.startswith('https://'):
            # we have a website so the parameters should look like:
            # expected_origin="https://psono.example.com",
            # expected_rp_id="psono.example.com",
            expected_origin = webauthn.origin
            expected_rp_id = webauthn.rp_id
        else:
            # We have a browser extension where the rp_id in the response contains the scheme too, e.g. in chrome:
            # expected_origin="chrome-extension://nknmfipbcebafiaclacheccehghgikkk",
            # expected_rp_id="chrome-extension://nknmfipbcebafiaclacheccehghgikkk",
            expected_origin = webauthn.origin
            expected_rp_id = webauthn.origin

        try:
            registration_verification = verify_registration_response(
                credential=RegistrationCredential.parse_raw(credential),
                expected_challenge=decrypt_with_db_secret(webauthn.challenge).encode(),
                expected_origin=expected_origin,
                expected_rp_id=expected_rp_id,
            )
        except InvalidRegistrationResponse:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['webauthn'] = webauthn
        attrs['credential_id'] = registration_verification.credential_id
        attrs['credential_public_key'] = registration_verification.credential_public_key

        return attrs
