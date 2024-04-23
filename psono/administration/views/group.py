from django.db.models import Q, Count
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from django.core.paginator import Paginator

from ..app_settings import (
    UpdateGroupSerializer,
    DeleteGroupSerializer,
    ReadGroupSerializer
)
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Group, User_Group_Membership, Group_Share_Right


class GroupView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_group_info(self, group):

        memberships = []
        for m in User_Group_Membership.objects.filter(group=group).select_related('user').only("id", "accepted", "group_admin", "share_admin", "create_date", "user__id", "user__username", "user__public_key"):
            memberships.append({
                'id': m.id,
                'create_date': m.create_date,
                'accepted': m.accepted,
                'admin': m.group_admin,
                'share_admin': m.share_admin,
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
                'share_title': '',
                'share_type': '',
            })

        return {
            'id': group.id,
            'name': group.name,
            'is_managed': False,
            'forced_membership': group.forced_membership,
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

        serializer = ReadGroupSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        if group_id:
            group = serializer.validated_data.get('group')
            group_info = self.get_group_info(group)

            return Response(group_info, status=status.HTTP_200_OK)

        else:
            page = serializer.validated_data.get('page')
            page_size = serializer.validated_data.get('page_size')
            ordering = serializer.validated_data.get('ordering')
            search = serializer.validated_data.get('search')

            group_qs = Group.objects.annotate(member_count=Count('members__id'))

            if search:
                group_qs = group_qs.filter(Q(name__icontains=search))
            if ordering:
                group_qs = group_qs.order_by(ordering)

            count = None
            if page_size:
                paginator = Paginator(group_qs, page_size)
                count = paginator.count
                chosen_page = paginator.page(page)
                group_qs = chosen_page.object_list

            groups = []
            for g in group_qs:
                groups.append({
                    'id': g.id,
                    'create_date': g.create_date,
                    'name': g.name,
                    'member_count': g.member_count,
                    'is_managed': False,
                })

            return Response({
                'count': count,
                'groups': groups
            }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Updates a group

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = UpdateGroupSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group = serializer.validated_data.get('group')
        name = serializer.validated_data.get('name')

        group.name = name
        group.save()

        return Response({}, status=status.HTTP_200_OK)

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

        return Response({}, status=status.HTTP_200_OK)