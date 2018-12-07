from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.renderers import StaticHTMLRenderer

import nacl.secret
import nacl.encoding
import nacl.utils
import json

from ..utils import filter_as_json
from ..app_settings import (
    ReadSecretWithAPIKeySerializer,
)

class APIKeyAccessSecretView(GenericAPIView):

    renderer_classes = (StaticHTMLRenderer,)
    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

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

        if not secret_key:
            return Response(json.dumps({
                'data': secret.data.tobytes().decode(),
                'data_nonce': str(secret.data_nonce),
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
