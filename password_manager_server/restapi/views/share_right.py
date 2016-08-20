from ..utils import user_has_rights_on_share, is_uuid, get_all_inherited_rights
from share_tree import create_share_link
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from django.db.models import Q

from ..models import (
    Share, User_Share_Right, User, Data_Store
)

from ..app_settings import (
    UserShareRightSerializer
)

from ..authentication import TokenAuthentication

class ShareRightView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    own share right if the necessary access rights are granted
    and the user is the user of the share right

    Accept the following GET parameters: share_id (optional)
    Return a list of the shares or the share and the access rights or a message for an update of rights
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    serializer_class = UserShareRightSerializer


    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, request, uuid = None, *args, **kwargs):
        """
        Returns a specific Share_Right or a list of all the users Share_Rights

        :param request:
        :param uuid:
        :param args:
        :param kwargs:
        :return: 200 / 403
        """
        if not uuid:

            # Generate a list of a all share rights

            try:
                share_rights = User_Share_Right.objects.filter(Q(user=request.user)).distinct()
            except User_Share_Right.DoesNotExist:
                share_rights = []

            share_right_response = []

            for share_right in share_rights:
                share_right_response.append({
                    'id': share_right.id,
                    'title': share_right.title,
                    'title_nonce': share_right.title_nonce,
                    'key': share_right.key,
                    'key_nonce': share_right.key_nonce,
                    'read': share_right.read,
                    'write': share_right.write,
                    'grant': share_right.grant,
                    'share_id': share_right.share_id
                })

            # TODO get inherited share rights
            share_rights_inherited = []

            for share_right in share_rights_inherited:
                share_right_response.append({
                    'id': share_right.id,
                    'title': share_right.share_right.title,
                    'title_nonce': share_right.share_right.title_nonce,
                    'key': share_right.share_right.key,
                    'key_nonce': share_right.share_right.key_nonce,
                    'read': share_right.share_right.read,
                    'write': share_right.share_right.write,
                    'grant': share_right.share_right.grant,
                    'share_id': share_right.share_right.share_id,
                    'parent_share_right_id': share_right.share_right_id
                })

            response = {
                'share_rights': share_right_response
            }

            return Response(response,
                status=status.HTTP_200_OK)

        else:
            # TODO update according to inherit share rights

            # Returns the specified share right if the user is the user

            try:
                share_right = User_Share_Right.objects.get(pk=uuid)
                if share_right.owner_id != request.user.id and share_right.user_id != request.user.id:
                    return Response({"message":"You don't have permission to access or it does not exist.",
                                    "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)
            except User_Share_Right.DoesNotExist:
                return Response({"message":"You don't have permission to access or it does not exist.",
                                "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

            response = {
                'id': share_right.id,
                'title': share_right.title,
                'title_nonce': share_right.title_nonce,
                'key': share_right.key,
                'key_nonce': share_right.key_nonce,
                'read': share_right.read,
                'write': share_right.write,
                'grant': share_right.grant,
                'share_id': share_right.share_id
            }

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Create Share_Right

        Necessary Rights:
            - grant on share

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 201 / 403
        """

        # check permissions on share
        if not user_has_rights_on_share(request.user.id, request.data['share_id'], grant=True):
            return Response({"message":"You don't have permission to access or it does not exist.",
                            "resource_id": request.data['share_id']}, status=status.HTTP_403_FORBIDDEN)

        # check if user exists
        try:
            user = User.objects.get(pk=request.data['user_id'])
        except User.DoesNotExist:
            return Response({"message":"Target user does not exist.",
                            "resource_id": request.data['user_id']}, status=status.HTTP_403_FORBIDDEN)


        try:
            # try to update it
            user_share_right_obj = User_Share_Right.objects.get(share_id=request.data['share_id'],
                                                                user_id=request.data['user_id'])
            user_share_right_obj.owner = request.user

            serializer = UserShareRightSerializer(request.data)

            user_share_right_obj.read = serializer.data['read']
            user_share_right_obj.write = serializer.data['write']
            user_share_right_obj.grant = serializer.data['grant']
            user_share_right_obj.save()

            return Response({"share_right_id": str(user_share_right_obj.id)},
                            status=status.HTTP_200_OK)


        except User_Share_Right.DoesNotExist:

            # lets check if the user has already a path to access the share. if yes automatically approve rights
            accepted = None
            if len(list(get_all_inherited_rights(user.id, request.data['share_id']))) > 0:
                accepted = True

            # it does not yet exist, so lets create it
            serializer = UserShareRightSerializer(request.data)

            user_share_right_obj2 = User_Share_Right.objects.create(
                key=str(request.data['key']),
                key_nonce=str(request.data['key_nonce']),
                title=str(request.data['title']),
                title_nonce=str(request.data['title_nonce']),
                share_id=request.data['share_id'],
                owner=request.user,
                user=user,
                read=serializer.data['read'],
                write=serializer.data['write'],
                grant=serializer.data['grant'],
                accepted=accepted,
            )

        return Response({"share_right_id": str(user_share_right_obj2.id)},
            status=status.HTTP_201_CREATED)


    def delete(self, request, uuid=None, *args, **kwargs):
        """
        Delete a Share_Right obj

        Necessary Rights:
            - grant on share


        :param request:
        :param uuid: share_right_id
        :param args:
        :param kwargs:
        :return: 200 / 403
        """

        if not uuid:
            return Response({"message": "UUID for share_right not specified."}, status=status.HTTP_403_FORBIDDEN)

        # check if share_right exists
        try:
            share_right = User_Share_Right.objects.get(pk=uuid)
        except User_Share_Right.DoesNotExist:
            return Response({"message": "You don't have permission to access or it does not exist.",
                         "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        # check permissions on parent
        if not user_has_rights_on_share(request.user.id, share_right.share_id, grant=True):
            return Response({"message": "You don't have permission to access or it does not exist.",
                             "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        # delete it
        share_right.delete()

        return Response(status=status.HTTP_200_OK)


class ShareRightAcceptView(GenericAPIView):
    """
    Check the REST Token and the object permissions and updates the share right as accepted with new symmetric
    encryption key and nonce
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, uuid=None, *args, **kwargs):
        """
        Mark a Share_right as accepted. In addition update the share right with the new encryption key and deletes now
        unnecessary information like title.

        :param request:
        :param uuid: share_right_id
        :param args:
        :param kwargs:
        :return: 200 / 403
        """

        parent_share_id = None
        parent_datastore_id = None

        # Validate stuff
        if not uuid:
            return Response({"message": "UUID for share_right not specified."}, status=status.HTTP_404_NOT_FOUND)

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
            user_share_right_obj = User_Share_Right.objects.get(pk=uuid, user=request.user, accepted=None)

            if not user_share_right_obj.grant and 'parent_share_id' in request.data:
                return Response({"message": "You don't have permission to access it or it does not exist or you already accepted or declined this share.",
                                "resource_id": request.data['parent_share_id']}, status=status.HTTP_403_FORBIDDEN)

            if not create_share_link(request.data['link_id'], user_share_right_obj.share_id, parent_share_id,
                                     parent_datastore_id):
                return Response({"message": "Link id already exists.",
                                 "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

            user_share_right_obj.accepted = True
            user_share_right_obj.title = ''
            user_share_right_obj.title_nonce = ''
            user_share_right_obj.key_type = 'symmetric'
            user_share_right_obj.key = request.data['key']
            user_share_right_obj.key_nonce = request.data['key_nonce']
            user_share_right_obj.save()

        except User_Share_Right.DoesNotExist:
            return Response({
                                "message": "You don't have permission to access it or it does not exist or you already accepted or declined this share.",
                                "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        if user_share_right_obj.read:
            share = Share.objects.get(pk=user_share_right_obj.share_id)
            return Response({
                "share_id": share.id,
                "share_data": str(share.data),
                "share_data_nonce": share.data_nonce
            }, status=status.HTTP_200_OK)

        return Response({
            "share_id": user_share_right_obj.share_id
        }, status=status.HTTP_200_OK)


class ShareRightDeclineView(GenericAPIView):

    """
    Check the REST Token and the object permissions and updates the share right as declined and removes title and keys
    from the share right
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, uuid = None, *args, **kwargs):
        """
        Mark a Share_right as declined. In addition deletes now unnecessary information like title and encryption key.

        :param request:
        :param uuid: share_right_id
        :param args:
        :param kwargs:
        :return: 200 / 403 / 404
        """

        if not uuid:
            return Response({"message": "UUID for share not specified."}, status=status.HTTP_404_NOT_FOUND)

        try:
            user_share_right_obj = User_Share_Right.objects.get(id=uuid, user=request.user, accepted=None)

            user_share_right_obj.accepted = False
            user_share_right_obj.title = ''
            user_share_right_obj.title_nonce = ''
            user_share_right_obj.key_type = ''
            user_share_right_obj.key = ''
            user_share_right_obj.key_nonce = ''
            user_share_right_obj.save()

        except User_Share_Right.DoesNotExist:
            return Response({"message":"You don't have permission to access it or it does not exist or you already accepted or declined this share.",
                            "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

        return Response(status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
