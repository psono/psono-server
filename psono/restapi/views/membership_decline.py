from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..authentication import TokenAuthentication

from ..app_settings import (
    MembershipDeclineSerializer,
)

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)


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

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='DECLINE_MEMBERSHIP_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        membership_obj = serializer.validated_data.get('membership_obj')
        membership_obj.accepted = False
        membership_obj.save()

        log_info(logger=logger, request=request, status='HTTP_200_OK', event='DECLINE_MEMBERSHIP_SUCCESS', request_resource=request.data['membership_id'])

        return Response(status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
