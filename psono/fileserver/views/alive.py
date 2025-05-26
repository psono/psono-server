from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

import datetime

from restapi.authentication import FileserverAliveAuthentication
from ..permissions import IsFileserver

from ..app_settings import (
    FileserverAliveSerializer,
)

class AliveView(GenericAPIView):

    authentication_classes = (FileserverAliveAuthentication, )
    permission_classes = (IsFileserver,)
    allowed_methods = ('PUT', 'OPTIONS', 'HEAD')
    throttle_scope = 'fileserver_alive'

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return FileserverAliveSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Updates the "alive" value in the database
        """

        serializer = FileserverAliveSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        fileserver = request.user # A bit hacky, yet DRF stores whatever authenticates as user, yet in our case its a fileserver
        fileserver.valid_till=timezone.now()+datetime.timedelta(seconds=30)
        fileserver.save(update_fields=["valid_till"])

        return Response({}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)