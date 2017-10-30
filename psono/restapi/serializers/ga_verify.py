from django.conf import settings
import hashlib

from django.utils.http import urlsafe_base64_decode as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from ..models import Google_Authenticator
import nacl.utils
import nacl.secret
import nacl.encoding
import pyotp

class GAVerifySerializer(serializers.Serializer):
    ga_token = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate(self, attrs):

        ga_token = attrs.get('ga_token').lower().strip()

        if not ga_token.isdigit():
            msg = _('GA Tokens only contain digits.')
            raise exceptions.ValidationError(msg)

        token = self.context['request'].auth

        if token.active:
            msg = _('Token incorrect.')
            raise exceptions.ValidationError(msg)

        # prepare decryption
        secret_key = hashlib.sha256(settings.DB_SECRET.encode('utf-8')).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)

        ga_token_correct = False
        for ga in Google_Authenticator.objects.filter(user_id=token.user_id):
            encrypted_ga_secret = nacl.encoding.HexEncoder.decode(ga.secret)
            decrypted_ga_secret = crypto_box.decrypt(encrypted_ga_secret)
            totp = pyotp.TOTP(decrypted_ga_secret)
            if totp.verify(ga_token):
                ga_token_correct = True
                attrs['ga_token'] = ga
            break

        if not ga_token_correct:
            msg = _('GA Token incorrect.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs
