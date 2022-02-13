from django.utils.translation import gettext_lazy as _
from django.conf import settings
from rest_framework import serializers, exceptions
from ..fields import UUIDField
from urllib.parse import urlencode

from ..utils import decrypt_with_db_secret, duo_auth_auth, duo_auth_enroll_status
from ..models import Duo

class ActivateDuoSerializer(serializers.Serializer):
    duo_id = UUIDField(required=True)
    duo_token = serializers.CharField(max_length=6, min_length=6, required=False)

    def validate(self, attrs: dict) -> dict:

        duo_id = attrs.get('duo_id', '')
        duo_token = attrs.get('duo_token', None)

        try:
            duo = Duo.objects.get(pk=duo_id, user=self.context['request'].user, active=False)
        except Duo.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if settings.DUO_SECRET_KEY and duo.duo_host == '':
            duo_integration_key = settings.DUO_INTEGRATION_KEY
            duo_secret_key = settings.DUO_SECRET_KEY
            duo_host = settings.DUO_API_HOSTNAME

        else:
            duo_integration_key = duo.duo_integration_key
            duo_secret_key = decrypt_with_db_secret(duo.duo_secret_key)
            duo_host = duo.duo_host

        if duo.enrollment_activation_code:
            enrollment_status = duo_auth_enroll_status(duo_integration_key,
                                                       duo_secret_key, duo_host,
                                                       duo.enrollment_user_id, duo.enrollment_activation_code)

            if enrollment_status == 'invalid':
                duo.delete()
                if not Duo.objects.filter(active=True).exists():
                    self.context['request'].user.duo_enabled = False
                    self.context['request'].user.save()
                msg = _("Duo enrollment expired")
                raise exceptions.ValidationError(msg)

            if enrollment_status == 'waiting':
                # Pending activation
                msg = _("Scan the barcode first")
                raise exceptions.ValidationError(msg)

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

        attrs['duo'] = duo

        return attrs
