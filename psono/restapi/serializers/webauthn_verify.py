from rest_framework import serializers, exceptions
import nacl.encoding
from webauthn import verify_authentication_response
from webauthn.helpers.structs import AuthenticationCredential
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from ..models import Webauthn
from ..utils import decrypt_with_db_secret

class WebauthnVerifySerializer(serializers.Serializer):
    credential = serializers.CharField(required=True)

    def validate(self, attrs: dict) -> dict:

        credential = attrs.get('credential', '').strip()

        token = self.context['request'].auth

        parsed_credential = AuthenticationCredential.parse_raw(
            credential
        )

        credential_id = nacl.encoding.HexEncoder.encode(parsed_credential.raw_id).decode()

        try:
            webauthn = Webauthn.objects.get(credential_id=credential_id, user=self.context['request'].user)
        except Webauthn.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        try:
            verify_authentication_response(
                credential=parsed_credential,
                expected_challenge=decrypt_with_db_secret(webauthn.challenge).encode(),
                expected_rp_id=webauthn.rp_id,
                expected_origin=webauthn.origin,
                credential_public_key=nacl.encoding.HexEncoder.decode(webauthn.credential_public_key),
                credential_current_sign_count=0,
                require_user_verification=False,
            )
        except InvalidAuthenticationResponse:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs
