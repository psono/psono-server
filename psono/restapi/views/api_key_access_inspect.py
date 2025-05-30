from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.serializers import Serializer
from rest_framework.parsers import JSONParser
from rest_framework.parsers import MultiPartParser
from rest_framework.renderers import StaticHTMLRenderer

import json

from ..app_settings import (
    ReadAPIKeyInspectSerializer,
)

class APIKeyAccessInspectView(GenericAPIView):

    renderer_classes = (StaticHTMLRenderer,)
    permission_classes = (AllowAny,)
    parser_classes = [JSONParser]
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ReadAPIKeyInspectSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Returns all ids of available secrets
        """
        serializer = ReadAPIKeyInspectSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        api_key_secrets = serializer.validated_data.get('api_key_secrets')
        api_key = serializer.validated_data.get('api_key')
        api_key_secrets_list = []

        for api_key_secret in api_key_secrets:
            api_key_secrets_list.append({
                'secret_id': str(api_key_secret.secret_id),
                'write_date': api_key_secret.secret.write_date.isoformat(),
            })

        return Response(json.dumps({
            'allow_insecure_access': api_key.allow_insecure_access,
            'restrict_to_secrets': api_key.restrict_to_secrets,
            'read': api_key.read,
            'write': api_key.write,
            'api_key_secrets': api_key_secrets_list
        }), status=status.HTTP_200_OK)


    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
