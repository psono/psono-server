from django.db.models import Count
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    DeleteGroupSerializer
)
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Group


class GroupView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        """
        Returns a list of all groups

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        groups = []
        for g in  Group.objects.annotate(member_count=Count('members__id')).order_by('-create_date'):
            groups.append({
                'id': g.id,
                'create_date': g.create_date.strftime('%Y-%m-%d %H:%M:%S'),
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