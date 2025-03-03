import json

from rest_framework import serializers, exceptions
import nacl.encoding
from webauthn import verify_authentication_response
from webauthn import base64url_to_bytes
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from ..models import Webauthn
from ..utils import decrypt_with_db_secret

class WebauthnVerifySerializer(serializers.Serializer):
    credential = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        credential = attrs.get('credential', '').strip()

        token = self.context['request'].auth
        parsed_credential = json.loads(credential)

        credential_id = nacl.encoding.HexEncoder.encode(base64url_to_bytes(parsed_credential['rawId'])).decode()

        try:
            webauthn = Webauthn.objects.get(credential_id=credential_id, user=self.context['request'].user)
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
            verify_authentication_response(
                credential=credential,
                expected_challenge=decrypt_with_db_secret(webauthn.challenge).encode(),
                expected_rp_id=expected_rp_id,
                expected_origin=expected_origin,
                credential_public_key=nacl.encoding.HexEncoder.decode(webauthn.credential_public_key),
                credential_current_sign_count=0,
                require_user_verification=False,
            )
        except InvalidAuthenticationResponse:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs
