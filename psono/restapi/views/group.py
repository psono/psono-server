from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..utils import request_misses_uuid
from ..app_settings import (
    CreateGroupSerializer,
    UpdateGroupSerializer,
)
from ..models import (
    Group, User_Group_Membership
)
from ..authentication import TokenAuthentication

# import the logging
from ..utils import log_info
import logging
logger = logging.getLogger(__name__)

class GroupView(GenericAPIView):

    """
    Check the REST Token and returns a list of all groups or the specified groups details

    Return the user's public key
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, uuid = None, *args, **kwargs):
        """
        Returns either a list of all groups with own access privileges or the members specified group
        
        :param request:
        :type request:
        :param uuid:
        :type uuid:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 403
        :rtype:
        """

        if not uuid:

            # Generates a list of groups wherever the user has any rights for it

            try:
                memberships = User_Group_Membership.objects.select_related('group').filter(user=request.user).exclude(accepted=False).distinct()
            except User_Group_Membership.DoesNotExist:
                memberships = []

            response = []

            for membership in memberships:

                details = {
                    'group_id': membership.group_id,
                    'membership_id': membership.id,
                    'name': membership.group.name,
                    'public_key': membership.group.public_key,
                    'group_admin': membership.group_admin,
                    'accepted': membership.accepted
                }

                if membership.accepted:
                    details['secret_key'] = membership.secret_key
                    details['secret_key_nonce'] = membership.secret_key_nonce
                    details['secret_key_type'] = membership.secret_key_type
                    details['private_key'] = membership.private_key
                    details['private_key_nonce'] = membership.private_key_nonce
                    details['private_key_type'] = membership.private_key_type

                if membership.accepted is None:
                    details['user_id'] = membership.creator.id
                    details['user_username'] = membership.creator.username
                    details['share_right_grant'] = True
                    for right in membership.group.group_share_rights.all():
                        if not right.grant:
                            details['share_right_grant'] = False
                            break


                response.append(details)


            print(response)

            log_info(logger=logger, request=request, status='HTTP_200_OK', event='READ_ALL_GROUPS_SUCCESS')

            return Response({'groups': response},
                status=status.HTTP_200_OK)
        else:

            # Returns the specified share if the user has any rights for it and joins the user_share objects
            try:
                membership = User_Group_Membership.objects.get(user=request.user, group_id=uuid)
            except User_Group_Membership.DoesNotExist:

                log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN', event='READ_GROUP_NO_PERMISSION_ERROR')

                return Response({"message":"You don't have permission to access or it does not exist.",
                                 "resource_id": uuid}, status=status.HTTP_403_FORBIDDEN)

            members = []
            if membership.group_admin and membership.accepted:
                for m in membership.group.members.all():
                    members.append({
                        'id': m.user.id,
                        'membership_id': m.id,
                        'name': m.user.username,
                        'public_key': m.user.public_key,
                        'group_admin': m.group_admin,
                        'accepted': m.accepted,
                    })
            else:
                members.append({
                    'id': request.user.id,
                    'membership_id': membership.id,
                    'name': request.user.username,
                    'public_key': request.user.public_key,
                    'group_admin': membership.group_admin,
                    'accepted': membership.accepted,
                })

            group_share_rights = []

            if membership.accepted:
                for s in membership.group.group_share_rights.all():
                    group_share_rights.append({
                        'id': s.id,
                        'share_id': s.share_id,
                        'title': s.title,
                        'title_nonce': s.title_nonce,
                        'type': s.type,
                        'type_nonce': s.type_nonce,
                        'key': s.key,
                        'key_nonce': s.key_nonce,
                        'read': s.read,
                        'write': s.write,
                        'grant': s.grant,
                    })

            response = {
                'group_id': membership.group_id,
                'name': membership.group.name,
                'public_key': membership.group.public_key,
                'group_admin': membership.group_admin,
                'accepted': membership.accepted,
            }

            if membership.accepted:
                response['secret_key'] = membership.secret_key
                response['secret_key_nonce'] = membership.secret_key_nonce
                response['secret_key_type'] = membership.secret_key_type
                response['private_key'] = membership.private_key
                response['private_key_nonce'] = membership.private_key_nonce
                response['private_key_type'] = membership.private_key_type
                response['members'] = members
                response['group_share_rights'] = group_share_rights

            if membership.accepted is None:
                response['user_id'] = membership.creator.id
                response['user_username'] = membership.creator.username


            log_info(logger=logger, request=request, status='HTTP_200_OK', event='READ_GROUP_SUCCESS', request_resource=membership.group_id)

            return Response(response,
                status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Creates a group

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateGroupSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='CREATE_GROUP_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group = Group.objects.create(
            name = str(request.data['name']),
            public_key = str(request.data['public_key']),
        )

        User_Group_Membership.objects.create(
            user = request.user,
            group = group,
            creator = request.user,
            secret_key = str(request.data['secret_key']),
            secret_key_nonce = str(request.data['secret_key_nonce']),
            secret_key_type = 'symmetric',
            private_key = str(request.data['private_key']),
            private_key_nonce = str(request.data['private_key_nonce']),
            private_key_type = 'symmetric',
            group_admin = True,
            accepted = True,
        )

        log_info(logger=logger, request=request, status='HTTP_201_CREATED', event='CREATE_GROUP_SUCCESS', request_resource=group.id)

        return Response({
            "group_id": group.id,
            "name": str(request.data['name']),
            "secret_key": str(request.data['secret_key']),
            "secret_key_nonce": str(request.data['secret_key_nonce']),
            "secret_key_type": 'symmetric',
            "private_key": str(request.data['private_key']),
            "private_key_nonce": str(request.data['private_key_nonce']),
            "private_key_type": 'symmetric',
            "public_key": str(request.data['public_key']),
            "group_admin": True,
            "accepted": True,
        }, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a group

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = UpdateGroupSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='UPDATE_GROUP_ERROR', errors=serializer.errors)

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group = serializer.validated_data.get('group')
        name = serializer.validated_data.get('name')

        if name:
            group.name = name
            group.save()

        log_info(logger=logger, request=request, status='HTTP_200_OK', event='UPDATE_GROUP_SUCCESS', request_resource=group.id)

        return Response(status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a group

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400 / 403
        """

        if request_misses_uuid(request, 'group_id'):

            log_info(logger=logger, request=request, status='HTTP_400_BAD_REQUEST', event='DELETE_GROUP_NO_GROUP_ID_ERROR')

            return Response({"error": "IdNoUUID", 'message': "Group ID not in request"},
                                status=status.HTTP_400_BAD_REQUEST)

        # check if the group exists
        try:
            membership = User_Group_Membership.objects.get(group_id=request.data['group_id'], user=request.user, group_admin=True)
        except User_Group_Membership.DoesNotExist:

            log_info(logger=logger, request=request, status='HTTP_403_FORBIDDEN', event='DELETE_GROUP_NO_PERMISSION_ERROR')

            return Response({"message":"You don't have permission to access or it does not exist.",
                             "resource_id": request.data['group_id']}, status=status.HTTP_403_FORBIDDEN)


        log_info(logger=logger, request=request, status='HTTP_200_OK', event='DELETE_GROUP_SUCCESS', request_resource=request.data['group_id'])

        # delete it
        membership.group.delete()

        return Response(status=status.HTTP_200_OK)
