from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.serializers import Serializer

from ..app_settings import (
    ReadShardSerializer,
)

from ..authentication import TokenAuthentication


class ShardView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'GET':
            return ReadShardSerializer
        return Serializer

    def get(self, request, *args, **kwargs):


        serializer = ReadShardSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        shards = serializer.validated_data.get('shards')

        return Response({
            'shards': shards
        }, status=status.HTTP_200_OK)



    def put(self, *args, **kwargs):

        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):

        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):

        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
