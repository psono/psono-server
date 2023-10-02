from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from django.core.cache import cache
from django.conf import settings

from ..app_settings import (
    CreateGroupSerializer,
    UpdateGroupSerializer,
    DeleteGroupSerializer,
)
from ..models import (
    Group, User_Group_Membership
)
from ..authentication import TokenAuthentication

class GroupView(GenericAPIView):

    """
    Check the REST Token and returns a list of all groups or the specified groups details
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')


    def get_groups(self, request):
        # Generates a list of groups wherever the user has any rights for it
        memberships = User_Group_Membership.objects.select_related('group').filter(user=request.user).exclude(
            accepted=False).distinct()

        response = []

        for membership in memberships:

            details = {
                'membership_create_date': membership.create_date.isoformat(),
                'group_id': membership.group_id,
                'membership_id': membership.id,
                'name': membership.group.name,
                'public_key': membership.group.public_key,
                'group_admin': membership.group_admin,
                'share_admin': membership.share_admin,
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
                details['user_id'] = membership.creator.id if membership.creator is not None else ''
                details['user_username'] = membership.creator.username if membership.creator is not None else ''
                details['share_right_grant'] = True
                for right in membership.group.group_share_rights.all():
                    if not right.grant:
                        details['share_right_grant'] = False
                        break

            response.append(details)

        return response

    def get_group_details(self, request, membership):

        members = []
        if membership.accepted:
            for m in membership.group.members.all():
                members.append({
                    'id': m.user.id,
                    'membership_create_date': m.create_date.isoformat(),
                    'membership_id': m.id,
                    'name': m.user.username,
                    'public_key': m.user.public_key,
                    'group_admin': m.group_admin,
                    'share_admin': m.share_admin,
                    'accepted': m.accepted,
                })

        group_share_rights = []

        if membership.accepted:
            for s in membership.group.group_share_rights.all():
                group_share_rights.append({
                    'id': s.id,
                    'create_date': s.create_date.isoformat(),
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
            'share_admin': membership.share_admin,
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
            response['user_id'] = membership.creator.id if membership.creator is not None else ''
            response['user_username'] = membership.creator.username if membership.creator is not None else ''

        return response


    def get(self, request, group_id = None, *args, **kwargs):
        """
        Returns either a list of all groups with own access privileges or the members specified group
        
        :param request:
        :type request:
        :param group_id:
        :type group_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 403
        :rtype:
        """

        if not group_id:
            return Response({'groups': self.get_groups(request)},
                status=status.HTTP_200_OK)
        else:

            # Returns the specified group if the user has any rights for it
            try:
                membership = User_Group_Membership.objects.get(user=request.user, group_id=group_id)
            except User_Group_Membership.DoesNotExist:

                return Response({"message":"NO_PERMISSION_OR_NOT_EXIST",
                                 "resource_id": group_id}, status=status.HTTP_400_BAD_REQUEST)


            return Response(self.get_group_details(request, membership),
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

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group = Group.objects.create(
            name = str(request.data['name']),
            public_key = str(request.data['public_key']),
        )

        User_Group_Membership.objects.create(  #nosec B105, B106
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
            share_admin = True,
            accepted = True,
        )

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
            "share_admin": True,
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

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group = serializer.validated_data.get('group')
        name = serializer.validated_data.get('name')

        if name:
            group.name = name
            group.save()

        return Response(status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a group

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteGroupSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group = serializer.validated_data.get('group')

        if settings.CACHE_ENABLE:
            for member in group.members.only('id').all():
                cache_key = 'psono_user_status_' + str(member.user.id)
                cache.delete(cache_key)

        # delete it
        group.delete()

        return Response(status=status.HTTP_200_OK)
