from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Token
)

from ..app_settings import (
    YubikeyOTPVerifySerializer
)
from ..authentication import TokenAuthenticationAllowInactive

# import the logging
import logging
logger = logging.getLogger(__name__)


class YubikeyOTPVerifyView(GenericAPIView):

    authentication_classes = (TokenAuthenticationAllowInactive, )
    permission_classes = (IsAuthenticated,)
    serializer_class = YubikeyOTPVerifySerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'yubikey_otp_verify'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Validates a Yubikey OTP

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
                    'event': 'LOGIN_YUBIKEY_OTP_VERIFY_ERROR',
                    'errors': serializer.errors,
                    'user': request.user.username
                })

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # Yubikey OTP challenge has been solved, so lets update the token
        token = serializer.validated_data['token']
        token.yubikey_otp_2fa = False
        token.save()

        if settings.LOGGING_AUDIT:
            logger.info({
                'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                'request_method': request.META['REQUEST_METHOD'],
                'request_url': request.META['PATH_INFO'],
                'success': True,
                'status': 'HTTP_200_OK',
                'event': 'LOGIN_YUBIKEY_OTP_VERIFY_SUCCESS',
                'user': token.user.username
            })

        return Response(status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)