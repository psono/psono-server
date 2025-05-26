from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from ..permissions import IsAuthenticated
from ..models import (
    Token
)
from ..authentication import TokenAuthentication

class SessionView(GenericAPIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    token_model = Token
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        return Serializer

    def get(self, request, *args, **kwargs):
        """
        Lists all active sessions
        """

        sessions = []
        for session in self.token_model.objects.filter(user=request.user, valid_till__gt=timezone.now(), active=True):
            sessions.append({
                "id": str(session.id),
                "create_date": session.create_date.isoformat(),
                "device_description": session.device_description,
                "current_session": session.id == request.auth.id,
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