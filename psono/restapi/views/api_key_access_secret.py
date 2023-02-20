from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from django.conf import settings

import nacl.secret
import nacl.encoding
import nacl.utils
import json
import requests

from ..renderers import PlainJSONRenderer
from ..models import (
    Secret_History,
)
from ..utils import filter_as_json, decrypt_with_db_secret, encrypt_with_db_secret
from ..utils import is_valid_callback_url
from ..app_settings import (
    UpdateSecretWithAPIKeySerializer,
    ReadSecretWithAPIKeySerializer,
)

class APIKeyAccessSecretView(GenericAPIView):

    renderer_classes = (PlainJSONRenderer,)
    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Updates a secret.

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = UpdateSecretWithAPIKeySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        secret = serializer.validated_data.get('secret')
        user = serializer.validated_data.get('user')

        Secret_History.objects.create(
            secret = secret,
            data = secret.data,
            data_nonce = secret.data_nonce,
            user = user,
            type = secret.type,
            callback_url = secret.callback_url,
            callback_user = secret.callback_user,
            callback_pass = secret.callback_pass,
        )

        if serializer.validated_data['data']:
            secret.data = serializer.validated_data['data'].encode()
        if serializer.validated_data['data_nonce']:
            secret.data_nonce = str(serializer.validated_data['data_nonce'])

        if serializer.validated_data.get('callback_url', None) is not None:
            secret.callback_url = serializer.validated_data['callback_url']
        if serializer.validated_data.get('callback_user', None) is not None:
            secret.callback_user = serializer.validated_data['callback_user']
        if serializer.validated_data.get('callback_pass', None) is not None:
            secret.callback_pass = encrypt_with_db_secret(serializer.validated_data['callback_pass'])

        secret.save()

        if secret.callback_url and not settings.DISABLE_CALLBACKS and is_valid_callback_url(secret.callback_url):
            headers = {'content-type': 'application/json'}
            data = {
                'event': 'UPDATE_SECRET_SUCCESS',
                'secret_id': str(secret.id),
            }

            callback_pass = ''  #nosec -- not [B105:hardcoded_password_string]
            if secret.callback_user and secret.callback_pass:
                try:
                    callback_pass = decrypt_with_db_secret(secret.callback_pass)
                except:
                    callback_pass = secret.callback_pass

            if secret.callback_user and callback_pass:
                auth = (secret.callback_user, callback_pass)
            else:
                auth = None

            try:
                requests.post(secret.callback_url, data=data, headers=headers, auth=auth, timeout=5.0)
            except: # nosec
                pass

        return Response(json.dumps({}), status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        Returns a secret and decrypts it for the client.

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = ReadSecretWithAPIKeySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        secret = serializer.validated_data.get('secret')
        secret_key = serializer.validated_data.get('secret_key')
        json_filter = serializer.validated_data.get('json_filter')
        api_key_secret = serializer.validated_data.get('api_key_secret')



        if not secret_key:
            return Response(json.dumps({
                'data': secret.data.tobytes().decode(),
                'data_nonce': str(secret.data_nonce),
                'secret_key': api_key_secret.secret_key,
                'secret_key_nonce': api_key_secret.secret_key_nonce,
            }), status=status.HTTP_200_OK)

        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        decrypted_data_json = crypto_box.decrypt(nacl.encoding.HexEncoder.decode(secret.data),
                                        nacl.encoding.HexEncoder.decode(secret.data_nonce))

        if not json_filter:
            return Response(decrypted_data_json, status=status.HTTP_200_OK)

        filtered_data = filter_as_json(decrypted_data_json, json_filter)

        return Response(filtered_data, status=status.HTTP_200_OK)


    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
