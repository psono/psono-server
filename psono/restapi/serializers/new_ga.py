from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers, exceptions

class NewGASerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)

    def validate(self, attrs: dict) -> dict:


        title = attrs.get('title', '').strip()

        if settings.ALLOWED_SECOND_FACTORS and 'google_authenticator' not in settings.ALLOWED_SECOND_FACTORS:
            # TODO replace with SERVER_NOT_SUPPORT_GA
            msg = _('The server does not allow Google Authenticator.')
            raise exceptions.ValidationError(msg)

        attrs['title'] = title

        return attrs