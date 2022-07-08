from ..utils import calculate_user_rights_on_share
from uuid import UUID
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..models import (
    Share
)

from rest_framework.exceptions import PermissionDenied

from ..authentication import TokenAuthentication

class ShareRightsView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, request, share_id = None, *args, **kwargs):
        """
        Returns all share rights of a specified share. Including the share rights of other people as long as the user
        who requests it has the "grant" right, and is allowed to see them.

        :param request:
        :type request:
        :param share_id:
        :type share_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        if not share_id:

            return Response({"message": "UUID for share not specified."}, status=status.HTTP_404_NOT_FOUND)

        try:
            UUID(share_id, version=4)
        except ValueError:
            return Response({"message":"SHARE_ID_IS_NO_VALID_UUID"}, status=status.HTTP_400_BAD_REQUEST)

        # Returns the specified share rights if the user has any rights for it and joins the user_share objects
        try:
            share = Share.objects.get(pk=share_id)
        except Share.DoesNotExist:

            return Response({"message":"NO_PERMISSION_OR_NOT_EXIST"}, status=status.HTTP_403_FORBIDDEN)


        own_share_rights = calculate_user_rights_on_share(request.user.id, share_id)

        if not any([own_share_rights['read'], own_share_rights['write'], own_share_rights['grant']]):

            raise PermissionDenied({"message":"NO_PERMISSION_OR_NOT_EXIST"})

        user_share_rights = []
        group_share_rights = []


        for u in share.user_share_rights.exclude(creator__isnull=True, accepted__isnull=True).exclude(creator__isnull=True, accepted=False).all():

            right = {
                'id': u.id,
                'accepted': u.accepted,
                'read': u.read,
                'write': u.write,
                'grant': u.grant,
                'user_id': u.user_id,
                'share_id': u.share_id,
                'username': u.user.username,
            }

            user_share_rights.append(right)

        for u in share.group_share_rights.all():

            right = {
                'id': u.id,
                'accepted': True,
                'read': u.read,
                'write': u.write,
                'grant': u.grant,
                'group_id': u.group_id,
                'share_id': u.share_id,
                'group_name': u.group.name,
            }

            group_share_rights.append(right)

        response = {
            'id': share.id,
            'own_share_rights': own_share_rights,
            'user_share_rights': user_share_rights,
            'group_share_rights': group_share_rights
        }

        return Response(response, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
