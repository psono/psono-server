from django.db.models import Count
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    DeleteGroupSerializer
)
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Group, User_Group_Membership, Group_Share_Right


class GroupView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_group_info(self, group_id):

        try:
            group = Group.objects.get(pk=group_id)
        except Group.DoesNotExist:
            return None

        memberships = []
        for m in User_Group_Membership.objects.filter(group=group).select_related('user').only("id", "accepted", "group_admin", "create_date", "user__id", "user__username", "user__public_key"):
            memberships.append({
                'id': m.id,
                'create_date': m.create_date,
                'accepted': m.accepted,
                'admin': m.group_admin,
                'user_id': m.user.id,
                'username': m.user.username,
            })

        share_rights = []
        for m in Group_Share_Right.objects.filter(group=group).only("id", "create_date", "read", "write", "grant", "share_id"):
            share_rights.append({
                'id': m.id,
                'create_date': m.create_date,
                'read': m.read,
                'write': m.write,
                'grant': m.grant,
                'share_id': m.share_id,
            })

        return {
            'id': group.id,
            'name': group.name,
            'create_date': group.create_date,
            'public_key': group.public_key,

            'memberships': memberships,
            'share_rights': share_rights,
        }

    def get(self, request, group_id = None, *args, **kwargs):
        """
        Returns a list of all groups

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """
        if group_id:


            user_info = self.get_group_info(group_id)

            if not user_info:
                return Response({"error": "Group not found."}, status=status.HTTP_404_NOT_FOUND)

            return Response(user_info,
                status=status.HTTP_200_OK)

        else:

            groups = []
            for g in  Group.objects.annotate(member_count=Count('members__id')).order_by('-create_date'):
                groups.append({
                    'id': g.id,
                    'create_date': g.create_date,
                    'name': g.name,
                    'member_count': g.member_count,
                })

            return Response({
                'groups': groups
            }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


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

        # delete it
        group.delete()

        return Response(status=status.HTTP_200_OK)