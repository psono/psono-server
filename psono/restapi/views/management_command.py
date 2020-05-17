from io import StringIO

from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from django.core.management import call_command
from ..authentication import ManagementCommandAuthentication

from ..app_settings import (
    ManagementCommandSerializer,
)

class ManagementCommandView(GenericAPIView):
    authentication_classes = (ManagementCommandAuthentication, )
    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):

        serializer = ManagementCommandSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        command_name = serializer.validated_data.get('command_name')
        command_args = serializer.validated_data.get('command_args')

        out = StringIO()
        call_command(command_name, stdout=out, *command_args)

        return Response({
            'output': out.getvalue()
        }, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)