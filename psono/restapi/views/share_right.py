from ..utils import get_all_inherited_rights
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..models import (
    User_Share_Right,
    Group_Share_Right
)

from ..app_settings import (
    CreateShareRightSerializer,
    UpdateShareRightSerializer,
    DeleteShareRightSerializer,
)

from ..authentication import TokenAuthentication

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)

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

            user_share_rights = User_Share_Right.objects.filter(user=request.user, accepted=True).only("share_id", "read", "write", "grant")
            group_share_rights = Group_Share_Right.objects.raw("""SELECT gr.*
                FROM restapi_group_share_right gr
                    JOIN restapi_user_group_membership ms ON gr.group_id = ms.group_id
                WHERE ms.user_id = %(user_id)s
                    AND ms.accepted = true""", {
                'user_id': request.user.id,
            })


            share_right_index = {}
            share_right_response = []

            for share_right in user_share_rights:
                if share_right.share_id not in share_right_index:
                    share = {
                        'share_id': share_right.share_id,
                        'read': share_right.read,
                        'write': share_right.write,
                        'grant': share_right.grant,
                    }
                    share_right_response.append(share)
                    share_right_index[share_right.share_id] = share
                else:
                    share_right_index[share_right.share_id]['read'] = share_right_index[share_right.share_id]['read'] or share_right.read
                    share_right_index[share_right.share_id]['write'] = share_right_index[share_right.share_id]['write'] or share_right.write
                    share_right_index[share_right.share_id]['grant'] = share_right_index[share_right.share_id]['grant'] or share_right.grant


            for share_right in group_share_rights:
                if share_right.share_id not in share_right_index:
                    share = {
                        'share_id': share_right.share_id,
                        'read': share_right.read,
                        'write': share_right.write,
                        'grant': share_right.grant,
                    }
                    share_right_response.append(share)
                    share_right_index[share_right.share_id] = share
                else:
                    share_right_index[share_right.share_id]['read'] = share_right_index[share_right.share_id]['read'] or share_right.read
                    share_right_index[share_right.share_id]['write'] = share_right_index[share_right.share_id]['write'] or share_right.write
                    share_right_index[share_right.share_id]['grant'] = share_right_index[share_right.share_id]['grant'] or share_right.grant


            response = {
                'share_rights': share_right_response
            }

            log_info(logger=logger, request=request, status='HTTP_200_OK',
                     event='READ_GROUP_SHARE_RIGHTS_SUCCESS')

            return Response(response,
                status=status.HTTP_200_OK)

        else:
            # TODO update according to inherit share rights

            # Returns the specified share right if the user is the user

            try:
                share_right = User_Share_Right.objects.get(pk=uuid)
                if share_right.creator_id != request.user.id and share_right.user_id != request.user.id:

                    log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                             event='READ_GROUP_SHARE_RIGHT_NO_PERMISSION_FAILURE', request_resource=uuid)

                    return Response({"message":"You don't have permission to access or it does not exist.",
                                    "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)
            except User_Share_Right.DoesNotExist:

                log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN',
                         event='READ_GROUP_SHARE_RIGHT_NOT_EXIST_FAILURE', request_resource=uuid)

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

            log_info(logger=logger, request=request, status='HTTP_200_OK',
                     event='READ_GROUP_SHARE_RIGHT_SUCCESS', request_resource=uuid)

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
        :return: 201 / 400
        """

        # it does not yet exist, so lets create it
        serializer = CreateShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='CREATE_SHARE_RIGHT_ERROR', errors=serializer.errors)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        if serializer.validated_data.get('user_id', False):
            try:
                # Lets see if it already exists
                User_Share_Right.objects.get(share_id=serializer.validated_data['share_id'],
                                             user_id=serializer.validated_data['user_id'])

                log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST',
                         event='CREATE_USER_SHARE_DUPLICATE_ERROR')

                return Response({"message": "User Share Right already exists."}, status=status.HTTP_400_BAD_REQUEST)


            except User_Share_Right.DoesNotExist:

                # lets check if the user has already a path to access the share. if yes automatically approve rights
                accepted = None
                if len(list(get_all_inherited_rights(serializer.validated_data['user_id'], serializer.validated_data['share_id']))) > 0:
                    accepted = True

                share_right = User_Share_Right.objects.create(
                    key=serializer.validated_data['key'],
                    key_nonce=serializer.validated_data['key_nonce'],
                    title=serializer.validated_data['title'],
                    title_nonce=serializer.validated_data['title_nonce'],
                    type=serializer.validated_data['type'],
                    type_nonce=serializer.validated_data['type_nonce'],
                    share_id=serializer.validated_data['share_id'],
                    creator=request.user,
                    user=serializer.validated_data['user'],
                    read=serializer.validated_data['read'],
                    write=serializer.validated_data['write'],
                    grant=serializer.validated_data['grant'],
                    accepted=accepted,
                )

                log_info(logger=logger, request=request, status='HTTP_201_CREATED',
                         event='CREATE_USER_SHARE_RIGHT_SUCCESS', request_resource=share_right.id)
        else:
            try:
                # Lets see if it already exists
                Group_Share_Right.objects.get(share_id=serializer.validated_data['share_id'],
                                              group_id=serializer.validated_data['group_id'])

                log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST',
                         event='CREATE_GROUP_SHARE_DUPLICATE_ERROR')

                return Response({"message": "Group Share Right already exists."}, status=status.HTTP_400_BAD_REQUEST)

            except Group_Share_Right.DoesNotExist:

                share_right = Group_Share_Right.objects.create(
                    key=serializer.validated_data['key'],
                    key_nonce=serializer.validated_data['key_nonce'],
                    title=serializer.validated_data['title'],
                    title_nonce=serializer.validated_data['title_nonce'],
                    type=serializer.validated_data['type'],
                    type_nonce=serializer.validated_data['type_nonce'],
                    share_id=serializer.validated_data['share_id'],
                    creator=request.user,
                    group=serializer.validated_data['group'],
                    read=serializer.validated_data['read'],
                    write=serializer.validated_data['write'],
                    grant=serializer.validated_data['grant'],
                )

                log_info(logger=logger, request=request, status='HTTP_201_CREATED',
                         event='CREATE_GROUP_SHARE_RIGHT_SUCCESS', request_resource=share_right.id)

        return Response({"share_right_id": share_right.id},
                        status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Update Share_Right

        Necessary Rights:
            - grant on share

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        # it does not yet exist, so lets create it
        serializer = UpdateShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='UPDATE_SHARE_RIGHT_ERROR', errors=serializer.errors)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


        share_right_obj = serializer.validated_data['share_right_obj']

        share_right_obj.read = serializer.validated_data['read']
        share_right_obj.write = serializer.validated_data['write']
        share_right_obj.grant = serializer.validated_data['grant']
        share_right_obj.save()

        log_info(logger=logger, request=request, status='HTTP_200_OK',
                 event='UPDATE_SHARE_RIGHT_SUCCESS', request_resource=share_right_obj.id)

        return Response({"share_right_id": str(share_right_obj.id)},
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
        :return: 200 / 400
        """

        # it does not yet exist, so lets create it
        serializer = DeleteShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='DELETE_SHARE_RIGHT_ERROR', errors=serializer.errors)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


        share_right = serializer.validated_data['share_right']

        log_info(logger=logger, request=request, status='HTTP_200_OK',
                 event='DELETE_SHARE_RIGHT_SUCCESS', request_resource=share_right.id)

        # delete it
        share_right.delete()

        return Response(status=status.HTTP_200_OK)

