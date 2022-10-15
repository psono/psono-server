from django.utils.translation import gettext_lazy as _
from django.conf import settings
from rest_framework import serializers, exceptions
import pyotp

from ..models import Google_Authenticator
from ..utils import decrypt_with_db_secret


class GAVerifySerializer(serializers.Serializer):
    ga_token = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate(self, attrs: dict) -> dict:

        ga_token = attrs.get('ga_token', '').lower().strip()

        if not ga_token.isdigit():
            msg = _('GA Tokens only contain digits.')
            raise exceptions.ValidationError(msg)

        token = self.context['request'].auth

        gas = Google_Authenticator.objects.filter(user_id=token.user_id).all()
        if len(gas) < 1:
            msg = _('No Google Authenticator found.')
            raise exceptions.ValidationError(msg)

        ga_token_correct = False
        for ga in gas:
            decrypted_ga_secret = decrypt_with_db_secret(ga.secret)
            totp = pyotp.TOTP(decrypted_ga_secret.encode())
            if totp.verify(ga_token, valid_window=settings.TOTP_VALID_WINDOW):
                ga_token_correct = True
                break

        if not ga_token_correct:
            msg = _('GA Token incorrect.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs
