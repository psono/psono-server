from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from ..permissions import IsAuthenticated
from django.core.cache import cache
from django.conf import settings

from ..authentication import TokenAuthentication

from ..app_settings import (
    ShareRightAcceptSerializer,
)

class ShareRightAcceptView(GenericAPIView):
    """
    Check the REST Token and the object permissions and updates the share right as accepted with new symmetric
    encryption key and nonce
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ShareRightAcceptSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Mark a Share_right as accepted. In addition update the share right with the new encryption key

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = ShareRightAcceptSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user_share_right_obj = serializer.validated_data.get('user_share_right_obj')

        type = user_share_right_obj.type
        type_nonce = user_share_right_obj.type_nonce

        user_share_right_obj.accepted = True
        user_share_right_obj.type = ''
        user_share_right_obj.type_nonce = ''
        user_share_right_obj.key_type = serializer.validated_data.get('key_type')

        if serializer.validated_data.get('key', False):
            user_share_right_obj.key = serializer.validated_data.get('key')
        if serializer.validated_data.get('key_nonce', False):
            user_share_right_obj.key_nonce = serializer.validated_data.get('key_nonce')

        user_share_right_obj.save()

        if settings.CACHE_ENABLE:
            cache_key = 'psono_user_status_' + str(user_share_right_obj.user.id)
            cache.delete(cache_key)

        if user_share_right_obj.read:

            return Response({
                "share_id": user_share_right_obj.share.id,
                "share_data": user_share_right_obj.share.data.decode(),
                "share_data_nonce": user_share_right_obj.share.data_nonce,
                "share_type": type,
                "share_type_nonce": type_nonce
            }, status=status.HTTP_200_OK)

        return Response({
            "share_id": user_share_right_obj.share.id,
            "share_type": type,
            "share_type_nonce": type_nonce
        }, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


