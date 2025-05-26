from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from ..permissions import IsAuthenticated
from ..authentication import TokenAuthentication

class SessionKeyView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')
    throttle_scope = 'status_check'

    def get_serializer_class(self):
        return Serializer

    def get(self, request, *args, **kwargs):
        """
        Returns the session key for the current session
        """

        return Response({
            'session_key': request.auth.session_key,
        }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)