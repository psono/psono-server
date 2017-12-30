from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
import nacl.utils
from nacl.exceptions import CryptoError
import nacl.secret
import nacl.encoding

class ActivateTokenSerializer(serializers.Serializer):
    verification = serializers.CharField(required=True)
    verification_nonce = serializers.CharField(max_length=64, required=True)

    def validate(self, attrs: dict) -> dict:
        verification_hex = attrs.get('verification')
        verification = nacl.encoding.HexEncoder.decode(verification_hex)
        verification_nonce_hex = attrs.get('verification_nonce')
        verification_nonce = nacl.encoding.HexEncoder.decode(verification_nonce_hex)

        token = self.context['request'].auth

        if token.active:
            msg = _('Token incorrect.')
            raise exceptions.ValidationError(msg)

        if token.google_authenticator_2fa:
            msg = _('GA challenge unsolved.')
            raise exceptions.ValidationError(msg)

        if token.google_authenticator_2fa:
            msg = _('YubiKey challenge unsolved.')
            raise exceptions.ValidationError(msg)

        crypto_box = nacl.secret.SecretBox(token.secret_key, encoder=nacl.encoding.HexEncoder)

        try:
            decrypted = crypto_box.decrypt(verification, verification_nonce).decode()
        except CryptoError:
            msg = _('Verification code incorrect.')
            raise exceptions.ValidationError(msg)


        if token.user_validator != decrypted:
            msg = _('Verification code incorrect.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs