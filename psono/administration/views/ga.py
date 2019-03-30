from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    DeleteGASerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Google_Authenticator


class GaView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    serializer_class = DeleteGASerializer
    allowed_methods = ('DELETE', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a Google authenticator

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteGASerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        google_authenticator = serializer.validated_data.get('google_authenticator')

        # delete it
        google_authenticator.delete()

        if not Google_Authenticator.objects.filter(user_id=request.user.id, active=True).exists():
            request.user.google_authenticator_enabled = False

        return Response(status=status.HTTP_200_OK)
