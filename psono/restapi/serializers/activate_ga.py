from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions
import pyotp

from ..models import Google_Authenticator
from ..utils import decrypt_with_db_secret

class ActivateGASerializer(serializers.Serializer):
    google_authenticator_id = serializers.UUIDField(required=True)
    google_authenticator_token = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate(self, attrs: dict) -> dict:

        google_authenticator_id = attrs.get('google_authenticator_id')
        google_authenticator_token = attrs.get('google_authenticator_token').strip()

        if not google_authenticator_token.isdigit():
            msg = _('GA Tokens only contain digits.')
            raise exceptions.ValidationError(msg)

        try:
            google_authenticator = Google_Authenticator.objects.get(pk=google_authenticator_id, user=self.context['request'].user, active=False)
        except Google_Authenticator.DoesNotExist:
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        decrypted_ga_secret = decrypt_with_db_secret(google_authenticator.secret)
        totp = pyotp.TOTP(decrypted_ga_secret.encode())

        if not totp.verify(google_authenticator_token):
            msg = _("GA Token incorrect.")
            raise exceptions.ValidationError(msg)

        attrs['google_authenticator'] = google_authenticator

        return attrs
