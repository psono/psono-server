from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from django.conf import settings
from rest_framework.permissions import AllowAny

from ..authentication import TokenAuthentication


class IvaltSecret(GenericAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    # permission_classes = (AllowAny,)
    allowed_methods = ('GET')

    def get(self, request, *args, **kwargs):
        """
        Lists all Ivalt mobile numbers

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        if settings.IVALT_SECRET_KEY == '':
            return Response({"error": "IvaltSecretKey", 'message': "The Ivalt secret key is not "
                                                                   "available"},
                            status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'secret': settings.IVALT_SECRET_KEY,
        },
            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
