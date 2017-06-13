from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny

from ..app_settings import (
    VerifyEmailSerializer,
)

# import the logging
import logging
logger = logging.getLogger(__name__)

class VerifyEmailView(GenericAPIView):

    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    serializer_class = VerifyEmailSerializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Verifies the activation code sent via email and updates the user

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            if settings.LOGGING_AUDIT:
                logger.info({
                    'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                    'request_method': request.META['REQUEST_METHOD'],
                    'request_url': request.META['PATH_INFO'],
                    'success': False,
                    'status': 'HTTP_400_BAD_REQUEST',
                    'event': 'LOGIN_VERIFY_EMAIL_ERROR',
                    'errors': serializer.errors
                })

            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']
        user.is_email_active = True
        user.save()

        if settings.LOGGING_AUDIT:
            logger.info({
                'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                'request_method': request.META['REQUEST_METHOD'],
                'request_url': request.META['PATH_INFO'],
                'success': True,
                'status': 'HTTP_200_OK',
                'event': 'LOGIN_VERIFY_EMAIL_SUCCESS',
                'user': user.username
            })

        return Response({"success": "Successfully activated."},
                        status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)