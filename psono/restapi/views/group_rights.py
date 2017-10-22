from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..models import (
    Group_Share_Right
)

from ..app_settings import (
    ReadGroupRightsSerializer,
)

from ..authentication import TokenAuthentication

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)

class GroupRightsView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, request, group_id = None, *args, **kwargs):
        """
        Returns a list of all group rights accessible by the user or
        a list of all groups accessible by the user filtered for a specific group

        :param request:
        :type request:
        :param uuid:
        :type uuid:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = ReadGroupRightsSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='READ_GROUP_RIGHTS_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )


        group_id = serializer.validated_data.get('group_id', False)

        if group_id:
            try:
                share_rights = Group_Share_Right.objects.only("group_id", "share_id", "read", "write", "grant").get(user_id=request.user.id, group_id=group_id)
            except Group_Share_Right.DoesNotExist:
                share_rights = []
        else:
            try:
                share_rights = Group_Share_Right.objects.raw("""SELECT gr.id, gr.group_id, gr.share_id, gr.read, gr.write, gr.grant
                    FROM restapi_group_share_right gr
                        JOIN restapi_user_group_membership ms ON gr.group_id = ms.group_id
                    WHERE ms.user_id = %(user_id)s
                        AND ms.accepted = true""", {
                    'user_id': request.user.id,
                })
            except Group_Share_Right.DoesNotExist:
                share_rights = []

        group_rights = []
        for right in share_rights:
            group_rights.append({
                'id': str(right.id),
                'group_id': str(right.group_id),
                'share_id': str(right.share_id),
                'read': right.read,
                'write': right.write,
                'grant': right.grant,
            })


        log_info(logger=logger, request=request, status='HTTP_200_OK',
                 event='READ_GROUP_RIGHTS_SUCCESS', request_resource=group_id)

        return Response({
            'group_rights': group_rights
        }, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
