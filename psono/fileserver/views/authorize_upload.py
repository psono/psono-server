from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from restapi.authentication import FileserverAuthentication
from ..permissions import IsFileserver
from ..app_settings import AuthorizeUploadSerializer

class AuthorizeUploadView(GenericAPIView):

    authentication_classes = (FileserverAuthentication, )
    permission_classes = (IsFileserver,)
    allowed_methods = ('PUT', 'OPTIONS', 'HEAD')
    throttle_scope = 'fileserver'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Unpacks the authorization information. Checks the user permission (e.g. quota).

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = AuthorizeUploadSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )


        return Response({

        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)