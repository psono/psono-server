from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions
from restapi.fields import UUIDField
from urllib.parse import urlencode


class AuthorizeUploadSerializer(serializers.Serializer):
    # duo_id = UUIDField(required=True)
    # duo_token = serializers.CharField(max_length=6, min_length=6, required=False)

    def validate(self, attrs: dict) -> dict:

        # duo_id = attrs.get('duo_id')
        # duo_token = attrs.get('duo_token', None)
        #
        # try:
        #     duo = Duo.objects.get(pk=duo_id, user=self.context['request'].user, active=False)
        # except Duo.DoesNotExist:
        #     msg = _("You don't have permission to access or it does not exist.")
        #     raise exceptions.ValidationError(msg)
        #
        # enrollment_status = duo_auth_enroll_status(duo.duo_integration_key, decrypt_with_db_secret(duo.duo_secret_key), duo.duo_host, duo.enrollment_user_id, duo.enrollment_activation_code)
        #
        # if enrollment_status == 'invalid':
        #     duo.delete()
        #     msg = _("Duo enrollment expired")
        #     raise exceptions.ValidationError(msg)
        #
        # if enrollment_status == 'waiting':
        #     # Pending activation
        #     msg = _("Scan the barcode first")
        #     raise exceptions.ValidationError(msg)
        #
        # if duo_token is not None:
        #     factor = 'passcode'
        #     device = None
        # else:
        #     factor = 'push'
        #     device = 'auto'
        #
        # username, domain = self.context['request'].user.username.split("@")
        #
        # duo_auth_return = duo_auth_auth(
        #     integration_key=duo.duo_integration_key,
        #     secret_key=decrypt_with_db_secret(duo.duo_secret_key),
        #     host=duo.duo_host,
        #     user_id=duo.enrollment_user_id,
        #     factor=factor,
        #     device=device,
        #     pushinfo=urlencode({'Host': domain}),
        #     passcode=duo_token
        # )
        #
        # if 'result' not in duo_auth_return or duo_auth_return['result'] != 'allow':
        #     if 'status_msg' in duo_auth_return:
        #         msg = _(duo_auth_return['status_msg'])
        #     elif 'error' in duo_auth_return:
        #         msg = _(duo_auth_return['error'])
        #     else:
        #         msg = _('Validation failed.')
        #     raise exceptions.ValidationError(msg)
        #
        # attrs['duo'] = duo

        return attrs
