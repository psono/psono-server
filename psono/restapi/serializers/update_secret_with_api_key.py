from rest_framework import serializers, exceptions

import json
import nacl.secret
import nacl.encoding
import nacl.utils

from ..utils import user_has_rights_on_secret
from ..fields import UUIDField
from ..models import API_Key_Secret


class UpdateSecretWithAPIKeySerializer(serializers.Serializer):
    api_key_id = UUIDField(required=True)
    secret_id = UUIDField(required=True)
    api_key_secret_key = serializers.CharField(required=False)

    data = serializers.CharField(required=False)
    data_nonce = serializers.CharField(required=False, max_length=64)
    callback_url = serializers.CharField(required=False, max_length=2048, allow_blank=True)
    callback_user = serializers.CharField(required=False, max_length=128, allow_blank=True)
    callback_pass = serializers.CharField(required=False, max_length=128, allow_blank=True)

    insecure_data = serializers.CharField(required=False)

    def validate(self, attrs: dict) -> dict:

        api_key_id = attrs.get('api_key_id')
        secret_id = attrs.get('secret_id')
        api_key_secret_key = attrs.get('api_key_secret_key', False)
        insecure_data = attrs.get('insecure_data', '')

        data = attrs.get('data', False)
        data_nonce = attrs.get('data_nonce', False)

        try:
            api_key_secret = API_Key_Secret.objects.select_related('secret', 'api_key', 'api_key__user').get(api_key_id=api_key_id, secret_id=secret_id, api_key__write=True, api_key__active=True, api_key__user__is_active=True)
            api_key = api_key_secret.api_key
            user = api_key.user
            secret = api_key_secret.secret
        except API_Key_Secret.DoesNotExist:
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        if api_key_secret_key and not api_key.allow_insecure_access:
            msg = "INSECURE_ACCESS_NOT_ALLOWED"
            raise exceptions.ValidationError(msg)

        if not user_has_rights_on_secret(api_key.user_id, secret.id, None, True):
            msg = "NO_PERMISSION_OR_NOT_EXIST"
            raise exceptions.ValidationError(msg)

        secret_key = None
        if api_key_secret_key:
            try:
                crypto_box = nacl.secret.SecretBox(api_key_secret_key, encoder=nacl.encoding.HexEncoder)
                secret_key = crypto_box.decrypt(nacl.encoding.HexEncoder.decode(api_key_secret.secret_key), nacl.encoding.HexEncoder.decode(api_key_secret.secret_key_nonce))
            except:
                msg = "API_KEY_SECRET_KEY_INVALID"
                raise exceptions.ValidationError(msg)

            if insecure_data:
                try:
                    json.loads(insecure_data)
                except:
                    msg = "API_KEY_SECRET_KEY_SPECIFIED_YET_INSECURE_DATA_NO_JSON"
                    raise exceptions.ValidationError(msg)

                secret_crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
                nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                encrypted_secret_full = secret_crypto_box.encrypt(insecure_data.encode("utf-8"), nonce)
                encrypted_secret = encrypted_secret_full[len(nonce):]

                data = nacl.encoding.HexEncoder.encode(encrypted_secret).decode()
                data_nonce = nacl.encoding.HexEncoder.encode(nonce).decode()

        attrs['secret'] = secret
        attrs['user'] = user
        attrs['api_key_secret'] = api_key_secret
        attrs['data'] = data
        attrs['data_nonce'] = data_nonce
        attrs['secret_key'] = secret_key

        return attrs