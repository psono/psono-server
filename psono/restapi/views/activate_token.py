from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Token
)

from ..app_settings import (
    ActivateTokenSerializer,
)
from ..authentication import TokenAuthenticationAllowInactive

import nacl.encoding
import nacl.utils
import nacl.secret
import hashlib

# import the logging
import logging
logger = logging.getLogger(__name__)

class ActivateTokenView(GenericAPIView):

    authentication_classes = (TokenAuthenticationAllowInactive, )
    permission_classes = (IsAuthenticated,)
    serializer_class = ActivateTokenSerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Activates a token

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """
        serializer = self.get_serializer(data=self.request.data)

        if not serializer.is_valid():

            if settings.LOGGING_AUDIT:
                logger.info({
                    'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                    'request_method': request.META['REQUEST_METHOD'],
                    'request_url': request.META['PATH_INFO'],
                    'success': False,
                    'status': 'HTTP_400_BAD_REQUEST',
                    'event': 'LOGIN_ACTIVATE_TOKEN_ERROR',
                    'errors': serializer.errors,
                    'user': request.user.username
                })

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        token = serializer.validated_data['token']

        token.active = True
        token.user_validator = None
        token.save()

        # decrypt user email address
        secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        encrypted_email = nacl.encoding.HexEncoder.decode(token.user.email)
        decrypted_email = crypto_box.decrypt(encrypted_email)

        if settings.LOGGING_AUDIT:
            logger.info({
                'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                'request_method': request.META['REQUEST_METHOD'],
                'request_url': request.META['PATH_INFO'],
                'success': True,
                'status': 'HTTP_200_OK',
                'event': 'LOGIN_ACTIVATE_TOKEN_SUCCESS',
                'user': request.user.username
            })

        return Response({
            "user": {
                "id": token.user.id,
                "email": decrypted_email,
                "secret_key": token.user.secret_key,
                "secret_key_nonce": token.user.secret_key_nonce
            }
        },status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)