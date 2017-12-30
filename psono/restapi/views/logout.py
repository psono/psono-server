from django.conf import settings
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


class LogoutView(GenericAPIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = LogoutSerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request):
        """
        Delete the current used token object.

        Accepts/Returns nothing.

        :param request:
        :type request:
        :return:
        :rtype:
        """


        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        session_id = serializer.validated_data.get('session_id', False)
        if session_id:
            try:
                self.token_model.objects.filter(id=session_id, user=request.user).delete()
            except:
                pass
        else:
            try:
                token_hash = serializer.validated_data['token_hash']
                self.token_model.objects.filter(key=token_hash, user=request.user).delete()
            except:
                pass

        return Response({"success": "Successfully logged out."},
                        status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)








