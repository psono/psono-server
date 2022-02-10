from django.utils.crypto import constant_time_compare

from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, exceptions
import nacl.utils
from nacl.exceptions import CryptoError
import nacl.secret
import nacl.encoding

class ActivateTokenSerializer(serializers.Serializer):
    verification = serializers.CharField(required=True)
    verification_nonce = serializers.CharField(max_length=64, required=True)

    def validate(self, attrs: dict) -> dict:
        verification_hex = attrs.get('verification', '')
        verification = nacl.encoding.HexEncoder.decode(verification_hex)
        verification_nonce_hex = attrs.get('verification_nonce', '')
        verification_nonce = nacl.encoding.HexEncoder.decode(verification_nonce_hex)

        token = self.context['request'].auth

        if token.active:
            # TODO Replace with TOKEN_INCORRECT
            msg = _('Token incorrect.')
            raise exceptions.ValidationError(msg)

        if token.google_authenticator_2fa:
            # TODO Replace with GA_CHALLENGE_UNSOLVED
            msg = _('GA challenge unsolved.')
            raise exceptions.ValidationError(msg)

        if token.duo_2fa:
            # TODO Replace with DUO_CHALLENGE_UNSOLVED
            msg = _('Duo challenge unsolved.')
            raise exceptions.ValidationError(msg)

        if token.yubikey_otp_2fa:
            # TODO Replace with YUBIKEY_CHALLENGE_UNSOLVED
            msg = _('YubiKey challenge unsolved.')
            raise exceptions.ValidationError(msg)

        crypto_box = nacl.secret.SecretBox(token.secret_key, encoder=nacl.encoding.HexEncoder)

        try:
            decrypted = crypto_box.decrypt(verification, verification_nonce).decode()
        except CryptoError:
            # TODO Replace with VERIFICATION_CODE_INCORRECT
            msg = _('Verification code incorrect.')
            raise exceptions.ValidationError(msg)


        if not constant_time_compare(token.user_validator, decrypted):
            # TODO Replace with VERIFICATION_CODE_INCORRECT
            msg = _('Verification code incorrect.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs