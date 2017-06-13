from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from ..models import (
    Token
)

from ..app_settings import (
    GAVerifySerializer
)

# import the logging
import logging
logger = logging.getLogger(__name__)

class GAVerifyView(GenericAPIView):

    permission_classes = (AllowAny,)
    serializer_class = GAVerifySerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'ga_verify'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Validates a Google Authenticator based OATH-TOTP

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
                    'event': 'LOGIN_GA_VERIFY_ERROR',
                    'errors': serializer.errors,
                    'user': request.user.username
                })

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # Google Authenticator challenge has been solved, so lets update the token
        token = serializer.validated_data['token']
        token.google_authenticator_2fa = False
        token.save()

        if settings.LOGGING_AUDIT:
            logger.info({
                'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                'request_method': request.META['REQUEST_METHOD'],
                'request_url': request.META['PATH_INFO'],
                'success': True,
                'status': 'HTTP_200_OK',
                'event': 'LOGIN_GA_VERIFY_SUCCESS',
                'user': token.user.username
            })

        return Response(status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)