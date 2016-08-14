from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..models import (
    Share
)

from ..app_settings import (
    UserShareRightSerializer
)
from rest_framework.exceptions import PermissionDenied

from ..authentication import TokenAuthentication

class ShareRightsView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    the share rights of a specified share if the necessary access rights are granted

    Accept the following GET parameters: share_id
    Return a list of the share rights for the specified share
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = UserShareRightSerializer

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, request, uuid = None, *args, **kwargs):
        # TODO update according to inherit share rights

        if not uuid:
            return Response({"message": "UUID for share not specified."}, status=status.HTTP_404_NOT_FOUND)

        else:

            # Returns the specified share rights if the user has any rights for it and joins the user_share objects

            try:
                share = Share.objects.get(pk=uuid)
            except Share.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

            own_share_right = {
                'id': [],
                'accepted': False,
                'read': False,
                'write': False,
                'grant': False,
                'user_id': [],
                'share_id': uuid,
                'email': [],
            }
            user_share_rights = []
            user_share_rights_inherited = []
            user_has_specific_rights = False


            for u in share.user_share_rights.all():

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

                if u.user_id == request.user.id and (u.read or u.write or u.grant):
                    user_has_specific_rights = True
                    own_share_right = right

                user_share_rights.append(right)

            # TODO Get inherited share rights
            user_share_right_inherit = []


            for u in user_share_right_inherit:
                right = {
                    'id': u.id,
                    'accepted': u.share_right.accepted,
                    'read': u.share_right.read,
                    'write': u.share_right.write,
                    'grant': u.share_right.grant,
                    'user_id': u.share_right.user_id,
                    'share_id': u.share_id,
                    'username': u.user.username,
                }

                if not user_has_specific_rights and u.user_id == request.user.id and\
                        (u.share_right.read or u.share_right.write or u.share_right.grant):
                    own_share_right['id'].push = right['id']
                    own_share_right['accepted'] = own_share_right['accepted'] or right['accepted']
                    own_share_right['read'] = own_share_right['read'] or right['read']
                    own_share_right['write'] = own_share_right['accepted'] or right['write']
                    own_share_right['grant'] = own_share_right['accepted'] or right['grant']
                    own_share_right['user_id'].push = right['user_id']
                    own_share_right['email'].push = right['email']

                user_share_rights_inherited.append(right)

            if not own_share_right['grant']:
                raise PermissionDenied({"message":"You don't have permission to access",
                                "resource_id": share.id})

            response = {
                'id': share.id,
                'own_share_rights': own_share_right,
                'user_share_rights': user_share_rights,
                'user_share_rights_inherited': user_share_rights_inherited
            }

            return Response(response,
                status=status.HTTP_200_OK)
