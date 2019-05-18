from rest_framework import serializers, exceptions
from django.utils.translation import ugettext_lazy as _

import nacl.secret
import nacl.encoding
import nacl.utils

from ..utils import user_has_rights_on_secret
from ..fields import UUIDField
from ..models import API_Key_Secret


class ReadSecretWithAPIKeySerializer(serializers.Serializer):
    api_key_id = UUIDField(required=True)
    secret_id = UUIDField(required=True)
    api_key_secret_key = serializers.CharField(required=False)
    json_filter = serializers.CharField(required=False)

    def validate(self, attrs: dict) -> dict:

        api_key_id = attrs.get('api_key_id')
        secret_id = attrs.get('secret_id')
        api_key_secret_key = attrs.get('api_key_secret_key', False)
        json_filter = attrs.get('json_filter', '')

        try:
            api_key_secret = API_Key_Secret.objects.select_related('secret', 'api_key').get(api_key_id=api_key_id, secret_id=secret_id, api_key__read=True, api_key__active=True, api_key__user__is_active=True)
            api_key = api_key_secret.api_key
            secret = api_key_secret.secret
        except API_Key_Secret.DoesNotExist:
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        if api_key_secret_key and not api_key.allow_insecure_access:
            msg = _("Insecure access is not allowed for this api key.")
            raise exceptions.ValidationError(msg)

        if not user_has_rights_on_secret(api_key.user_id, secret.id, True, None):
            msg = _("NO_PERMISSION_OR_NOT_EXIST")
            raise exceptions.ValidationError(msg)

        secret_key = None
        if api_key_secret_key:
            try:
                crypto_box = nacl.secret.SecretBox(api_key_secret_key, encoder=nacl.encoding.HexEncoder)
                secret_key = crypto_box.decrypt(nacl.encoding.HexEncoder.decode(api_key_secret.secret_key), nacl.encoding.HexEncoder.decode(api_key_secret.secret_key_nonce))
            except:
                msg = _("api_key_secret_key invalid")
                raise exceptions.ValidationError(msg)

        json_filter = json_filter.strip()
        if json_filter:
            json_filter = json_filter.split('.')
        else:
            json_filter = []

        attrs['secret'] = secret
        attrs['api_key_secret'] = api_key_secret
        attrs['secret_key'] = secret_key
        attrs['json_filter'] = json_filter

        return attrs