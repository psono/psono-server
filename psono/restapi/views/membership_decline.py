from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from django.core.cache import cache
from django.conf import settings

from ..authentication import TokenAuthentication

from ..app_settings import (
    MembershipDeclineSerializer,
)


class MembershipDeclineView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Marks a membership as declined. In addition deletes now unnecessary information.

        :param request:
        :param uuid: share_right_id
        :param args:
        :param kwargs:
        :return: 200 / 403
        """

        serializer = MembershipDeclineSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        membership_obj = serializer.validated_data.get('membership_obj')
        membership_obj.accepted = False
        membership_obj.save()

        if settings.CACHE_ENABLE:
            cache_key = 'psono_user_status_' + str(membership_obj.user.id)
            cache.delete(cache_key)

        return Response(status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
