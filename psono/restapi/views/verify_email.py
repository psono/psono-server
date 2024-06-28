from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.parsers import JSONParser
from rest_framework.parsers import MultiPartParser

from ..app_settings import (
    VerifyEmailSerializer,
)

class VerifyEmailView(GenericAPIView):

    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    parser_classes = [JSONParser]

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
        :return: 200 / 400
        :rtype:
        """

        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']
        user.is_email_active = True
        user.save()

        return Response({"success": "Successfully activated."},
                        status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)