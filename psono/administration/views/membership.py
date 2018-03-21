from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    DeleteMembershipSerializer
)
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import User_Group_Membership


class MembershipView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        """
        Returns a list of all memberships

        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        memberships = []
        for g in  User_Group_Membership.objects.select_related('user', 'group').order_by('-create_date'):
            memberships.append({
                'id': g.id,
                'create_date': g.create_date.strftime('%Y-%m-%d %H:%M:%S'),
                'username': g.user.username,
                'group': g.group.name,
            })

        return Response({
            'memberships': memberships
        }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


    def delete(self, request, *args, **kwargs):
        """
        Deletes a membership

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteMembershipSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        membership = serializer.validated_data.get('membership')

        # delete it
        membership.delete()

        return Response(status=status.HTTP_200_OK)