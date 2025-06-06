import datetime

from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.serializers import Serializer
from rest_framework.parsers import JSONParser
from rest_framework.parsers import MultiPartParser
from rest_framework import status
from django.http import HttpResponse

from ..app_settings import (
    ReadAvatarImageSerializer,
)
class AvatarImageView(GenericAPIView):
    permission_classes = (AllowAny,)
    parser_classes = [JSONParser]
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')
    throttle_scope = 'avatar_image'

    def get_serializer_class(self):
        if self.request.method == 'GET':
            return ReadAvatarImageSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, request, user_id, avatar_id):

        serializer = ReadAvatarImageSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        mime_type = serializer.validated_data['mime_type']
        data = serializer.validated_data['data']
        response = HttpResponse(data, content_type=mime_type, status=status.HTTP_200_OK)
        max_age = 2592000  # 30 days in seconds
        response['Cache-Control'] = f'max-age={max_age}, public'
        response['Pragma'] = 'cache'
        expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=max_age)
        response['Expires'] = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
        return response
