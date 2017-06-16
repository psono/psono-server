from ..utils import user_has_rights_on_share, is_uuid, request_misses_uuid
from .share_tree import create_share_link
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..models import (
    User_Share_Right, Data_Store
)
from ..utils import readbuffer
from ..authentication import TokenAuthentication



class ShareRightAcceptView(GenericAPIView):
    """
    Check the REST Token and the object permissions and updates the share right as accepted with new symmetric
    encryption key and nonce
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Mark a Share_right as accepted. In addition update the share right with the new encryption key and deletes now
        unnecessary information like title.

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400 / 403
        """

        if request_misses_uuid(request, 'share_right_id'):
            return Response({"error": "IdNoUUID", 'message': "Share Right ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        parent_share_id = None
        parent_datastore_id = None

        if 'link_id' not in request.data:
            return Response({"error": "IdNoUUID", 'message': "link_id not in request"},
                            status=status.HTTP_400_BAD_REQUEST)

        if not is_uuid(request.data['link_id']):
            return Response({"error": "IdNoUUID", 'message': "link_id is no valid uuid"},
                            status=status.HTTP_400_BAD_REQUEST)

        if 'parent_share_id' not in request.data and 'parent_datastore_id' not in request.data:
            return Response(
                {"error": "NotInRequest", 'message': "No parent (share or datastore) has been provided as parent"},
                status=status.HTTP_400_BAD_REQUEST)

        if 'parent_share_id' in request.data and 'parent_datastore_id' in request.data:
            return Response(
                {"error": "InRequest", 'message': "Only one parent can exist, either a datastore or a share"},
                status=status.HTTP_400_BAD_REQUEST)

        if 'parent_share_id' in request.data and not is_uuid(request.data['parent_share_id']):
            return Response({"error": "IdNoUUID", 'message': "parent_share_id is no valid uuid"},
                            status=status.HTTP_400_BAD_REQUEST)

        if 'parent_datastore_id' in request.data and not is_uuid(request.data['parent_datastore_id']):
            return Response({"error": "IdNoUUID", 'message': "parent_datastore_id is no valid uuid"},
                            status=status.HTTP_400_BAD_REQUEST)

        # Check existence and rights:
        if 'parent_share_id' in request.data:
            parent_share_id = request.data['parent_share_id']
            if not user_has_rights_on_share(request.user.id, parent_share_id, write=True):
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": parent_share_id}, status=status.HTTP_403_FORBIDDEN)

        if 'parent_datastore_id' in request.data:
            parent_datastore_id = request.data['parent_datastore_id']
            try:
                Data_Store.objects.get(pk=parent_datastore_id, user=request.user)
            except Data_Store.DoesNotExist:
                return Response({"message": "You don't have permission to access it or it does not exist or you already accepted or declined this share.",
                                "resource_id": parent_datastore_id}, status=status.HTTP_403_FORBIDDEN)

        try:
            user_share_right_obj = User_Share_Right.objects.get(pk=request.data['share_right_id'], user=request.user, accepted=None)

            if not user_share_right_obj.grant and 'parent_share_id' in request.data:
                return Response({"message": "You don't have permission to access it or it does not exist or you already accepted or declined this share.",
                                "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

            if not create_share_link(request.data['link_id'], user_share_right_obj.share_id, parent_share_id,
                                     parent_datastore_id):
                return Response({"message": "Link id already exists.",
                                 "resource_id": request.data['share_right_id']}, status=status.HTTP_403_FORBIDDEN)

            type = user_share_right_obj.type
            type_nonce = user_share_right_obj.type_nonce

            user_share_right_obj.accepted = True
            user_share_right_obj.title = ''
            user_share_right_obj.title_nonce = ''
            user_share_right_obj.type = ''
            user_share_right_obj.type_nonce = ''
            user_share_right_obj.key_type = 'symmetric'
            user_share_right_obj.key = request.data['key']
            user_share_right_obj.key_nonce = request.data['key_nonce']
            user_share_right_obj.save()

        except User_Share_Right.DoesNotExist:
            return Response({
                                "message": "You don't have permission to access it or it does not exist or you already accepted or declined this share.",
                                "resource_id": request.data['share_right_id']}, status=status.HTTP_403_FORBIDDEN)

        if user_share_right_obj.read:
            return Response({
                "share_id": user_share_right_obj.share.id,
                "share_data": readbuffer(user_share_right_obj.share.data),
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


