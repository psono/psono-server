from django.utils.crypto import constant_time_compare

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
            msg = 'TOKEN_INCORRECT'
            raise exceptions.ValidationError(msg)

        if token.google_authenticator_2fa:
            msg = 'GA_CHALLENGE_UNSOLVED'
            raise exceptions.ValidationError(msg)

        if token.duo_2fa:
            msg = 'DUO_CHALLENGE_UNSOLVED'
            raise exceptions.ValidationError(msg)

        if token.yubikey_otp_2fa:
            msg = 'YUBIKEY_CHALLENGE_UNSOLVED'
            raise exceptions.ValidationError(msg)

        if token.webauthn_2fa:
            msg = 'WEBAUTHN_CHALLENGE_UNSOLVED'
            raise exceptions.ValidationError(msg)
        
        if token.ivalt_2fa:
            msg = 'IVALT_CHALLENGE_UNSOLVED'
            raise exceptions.ValidationError(msg)

        crypto_box = nacl.secret.SecretBox(token.secret_key, encoder=nacl.encoding.HexEncoder)

        try:
            decrypted = crypto_box.decrypt(verification, verification_nonce).decode()
        except CryptoError:
            msg = 'VERIFICATION_CODE_INCORRECT'
            raise exceptions.ValidationError(msg)


        if not constant_time_compare(token.user_validator, decrypted):
            msg = 'VERIFICATION_CODE_INCORRECT'
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs