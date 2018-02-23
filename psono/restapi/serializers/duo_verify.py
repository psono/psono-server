from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions

from urllib.parse import urlencode, quote_plus

from ..utils import decrypt_with_db_secret, duo_auth_auth, duo_auth_enroll_status

from ..models import Duo

class DuoVerifySerializer(serializers.Serializer):
    duo_token = serializers.CharField(max_length=6, min_length=6, required=False)

    def validate(self, attrs: dict) -> dict:

        duo_token = attrs.get('duo_token', None)

        token = self.context['request'].auth

        if token.active:
            msg = _('Token incorrect.')
            raise exceptions.ValidationError(msg)

        duos = Duo.objects.filter(user_id=token.user_id).all()
        if len(duos) < 1:
            msg = _('No duo found.')
            raise exceptions.ValidationError(msg)

        for duo in duos:
            enrollment_status = duo_auth_enroll_status(duo.duo_integration_key, decrypt_with_db_secret(duo.duo_secret_key), duo.duo_host, duo.enrollment_user_id, duo.enrollment_activation_code)

            if enrollment_status == 'invalid':
                # Never activated
                duo.delete()
                continue

            if enrollment_status == 'waiting':
                # Pending activation, so it does not count
                continue

            if duo_token is not None:
                factor = 'passcode'
                device = None
            else:
                factor = 'push'
                device = 'auto'

            username, domain = self.context['request'].user.username.split("@")

            duo_auth_return = duo_auth_auth(
                integration_key=duo.duo_integration_key,
                secret_key=decrypt_with_db_secret(duo.duo_secret_key),
                host=duo.duo_host,
                user_id=duo.enrollment_user_id,
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
                break

        attrs['token'] = token
        return attrs
