from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from django.core.cache import cache
from django.conf import settings

from ..authentication import TokenAuthentication

from ..app_settings import (
    ShareRightDeclineSerializer,
)

class ShareRightDeclineView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Mark a Share_right as declined. In addition deletes now unnecessary information like title and encryption key.

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 403
        """

        serializer = ShareRightDeclineSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user_share_right_obj = serializer.validated_data.get('user_share_right_obj')

        user_share_right_obj.accepted = False
        user_share_right_obj.title = ''
        user_share_right_obj.title_nonce = ''
        user_share_right_obj.type = ''
        user_share_right_obj.type_nonce = ''
        user_share_right_obj.key_type = ''
        user_share_right_obj.key = ''
        user_share_right_obj.key_nonce = ''
        user_share_right_obj.save()

        if settings.CACHE_ENABLE:
            cache_key = 'psono_user_status_' + str(user_share_right_obj.user.id)
            cache.delete(cache_key)

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
