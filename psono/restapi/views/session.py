from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from ..models import (
    Token
)

from ..app_settings import (
    LogoutSerializer,
)
from ..authentication import TokenAuthentication

from datetime import timedelta

# import the logging
import logging
logger = logging.getLogger(__name__)

class SessionView(GenericAPIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = LogoutSerializer
    token_model = Token
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):

        time_threshold = timezone.now() - timedelta(seconds=settings.TOKEN_TIME_VALID)

        sessions = []
        for session in self.token_model.objects.filter(user=request.user, create_date__gt=time_threshold, active=True):
            sessions.append({
                "id": str(session.id),
                "create_date": session.create_date.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "device_description": session.device_description,
                "current_session": session.id == request.auth.id,
            })

        if settings.LOGGING_AUDIT:
            logger.info({
                'ip': request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')),
                'request_method': request.META['REQUEST_METHOD'],
                'request_url': request.META['PATH_INFO'],
                'success': True,
                'status': 'HTTP_200_OK',
                'event': 'LIST_SESSIONS_SUCCESS',
                'user': request.user.username
            })

        return Response({
            'sessions': sessions
        }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)