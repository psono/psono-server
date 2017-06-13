from ..utils import user_has_rights_on_share, request_misses_uuid, get_all_inherited_rights
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from django.db.models import Q

from ..models import (
    User_Share_Right
)

from ..app_settings import (
    CreateUserShareRightSerializer,
    UpdateUserShareRightSerializer,
)

from ..authentication import TokenAuthentication

class ShareRightView(GenericAPIView):

    """
    Check the REST Token and the object permissions and returns
    only the share right of the user who requested it.

    Accept the following GET parameters: share_id (optional)
    Return a list of the shares or the share and the access rights or a message for an update of rights
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, uuid = None, *args, **kwargs):
        """
        Returns a specific Share_Right or a list of all the Share_Rights of the user who requested it

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
                    'type': share_right.type,
                    'type_nonce': share_right.type_nonce,
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
                    'type': share_right.share_right.type,
                    'type_nonce': share_right.share_right.type_nonce,
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
        :return: 201 / 403
        """

        # it does not yet exist, so lets create it
        serializer = CreateUserShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


        try:
            # Lets see if it already exists
            User_Share_Right.objects.get(share_id=serializer.validated_data['share_id'],
                                                                user_id=serializer.validated_data['user_id'])

            return Response({"message": "User Share Right already exists."}, status=status.HTTP_400_BAD_REQUEST)


        except User_Share_Right.DoesNotExist:

            # lets check if the user has already a path to access the share. if yes automatically approve rights
            accepted = None
            if len(list(get_all_inherited_rights(serializer.validated_data['user_id'], serializer.validated_data['share_id']))) > 0:
                accepted = True

            user_share_right_obj2 = User_Share_Right.objects.create(
                key=serializer.validated_data['key'],
                key_nonce=serializer.validated_data['key_nonce'],
                title=serializer.validated_data['title'],
                title_nonce=serializer.validated_data['title_nonce'],
                type=serializer.validated_data['type'],
                type_nonce=serializer.validated_data['type_nonce'],
                share_id=serializer.validated_data['share_id'],
                owner=request.user,
                user=serializer.validated_data['user'],
                read=serializer.validated_data['read'],
                write=serializer.validated_data['write'],
                grant=serializer.validated_data['grant'],
                accepted=accepted,
            )

        return Response({"share_right_id": str(user_share_right_obj2.id)},
            status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Update Share_Right

        Necessary Rights:
            - grant on share

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 403
        """

        # it does not yet exist, so lets create it
        serializer = UpdateUserShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


        try:
            user_share_right_obj = User_Share_Right.objects.get(share_id=serializer.validated_data['share_id'],
                                                                user_id=serializer.validated_data['user_id'])
        except User_Share_Right.DoesNotExist:
            return Response({"message": "You don't have permission to access or it does not exist."},
                            status=status.HTTP_403_FORBIDDEN)

        user_share_right_obj.owner = request.user

        user_share_right_obj.read = serializer.validated_data['read']
        user_share_right_obj.write = serializer.validated_data['write']
        user_share_right_obj.grant = serializer.validated_data['grant']
        user_share_right_obj.save()

        return Response({"share_right_id": str(user_share_right_obj.id)},
                        status=status.HTTP_200_OK)





    def delete(self, request, *args, **kwargs):
        """
        Delete a Share_Right obj

        Necessary Rights:
            - grant on share


        :param request:
        :param uuid: share_right_id
        :param args:
        :param kwargs:
        :return: 200 / 400 / 403
        """

        if request_misses_uuid(request, 'share_right_id'):
            return Response({"error": "IdNoUUID", 'message': "Share Right ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        if not request.data['share_right_id']:
            return Response({"message": "UUID for share_right not specified."}, status=status.HTTP_403_FORBIDDEN)

        # check if share_right exists
        try:
            share_right = User_Share_Right.objects.get(pk=request.data['share_right_id'])
        except User_Share_Right.DoesNotExist:
            return Response({"message": "You don't have permission to access or it does not exist.",
                         "resource_id": request.data['share_right_id']}, status=status.HTTP_403_FORBIDDEN)

        # check permissions on parent
        if not user_has_rights_on_share(request.user.id, share_right.share_id, grant=True):
            return Response({"message": "You don't have permission to access or it does not exist.",
                             "resource_id": request.data['share_right_id']}, status=status.HTTP_403_FORBIDDEN)

        # delete it
        share_right.delete()

        return Response(status=status.HTTP_200_OK)

