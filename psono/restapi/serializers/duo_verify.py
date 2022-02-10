from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers, exceptions

from urllib.parse import urlencode, quote_plus

from ..utils import decrypt_with_db_secret, duo_auth_auth, duo_auth_enroll_status

from ..models import Duo

class DuoVerifySerializer(serializers.Serializer):
    duo_token = serializers.CharField(max_length=6, min_length=6, required=False)

    def validate(self, attrs: dict) -> dict:

        duo_token = attrs.get('duo_token', None)

        token = self.context['request'].auth

        duos = Duo.objects.filter(user_id=token.user_id).all()
        if len(duos) < 1:
            msg = _('No duo found.')
            raise exceptions.ValidationError(msg)

        duo_solved = False

        for duo in duos:

            if settings.DUO_SECRET_KEY and duo.duo_host == '':
                duo_integration_key = settings.DUO_INTEGRATION_KEY
                duo_secret_key = settings.DUO_SECRET_KEY
                duo_host = settings.DUO_API_HOSTNAME

            else:
                duo_integration_key = duo.duo_integration_key
                duo_secret_key = decrypt_with_db_secret(duo.duo_secret_key)
                duo_host = duo.duo_host

            if duo_token is not None:
                factor = 'passcode'
                device = None
            else:
                factor = 'push'
                device = 'auto'

            username, domain = self.context['request'].user.username.split("@")

            duo_auth_return = duo_auth_auth(
                integration_key=duo_integration_key,
                secret_key=duo_secret_key,
                host=duo_host,
                username=username,
                factor=factor,
                device=device,
                pushinfo=urlencode({'Host': domain}),
                passcode=duo_token
            )

            if 'result' not in duo_auth_return or duo_auth_return['result'] != 'allow':

                if 'status_msg' in duo_auth_return:
                    msg = _(duo_auth_return['status_msg'])
                elif 'error' in duo_auth_return:
                    msg = _(duo_auth_return['error'])
                else:
                    msg = _('Validation failed.')
                raise exceptions.ValidationError(msg)
            else:
                duo_solved = True
                break

        if not duo_solved:
            msg = _('Validation failed.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs
