from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from ..app_settings import (
    CreateMembershipSerializer,
    UpdateMembershipSerializer,
    DeleteMembershipSerializer,
)
from ..models import (
    User_Group_Membership
)
from ..authentication import TokenAuthentication

class MembershipView(GenericAPIView):

    """
    Manages group memberships
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



    def put(self, request, *args, **kwargs):
        """
        Creates a new group membership

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateMembershipSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        membership = User_Group_Membership.objects.create(
            user_id = serializer.validated_data['user_id'],
            group_id = serializer.validated_data['group_id'],
            creator = request.user,
            secret_key = str(serializer.validated_data['secret_key']),
            secret_key_nonce = str(serializer.validated_data['secret_key_nonce']),
            secret_key_type = str(serializer.validated_data['secret_key_type']),
            private_key = str(serializer.validated_data['private_key']),
            private_key_nonce = str(serializer.validated_data['private_key_nonce']),
            private_key_type = str(serializer.validated_data['private_key_type']),
            group_admin = serializer.validated_data['group_admin'],
        )

        return Response({'membership_id': membership.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a group membership

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        serializer = UpdateMembershipSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        membership = serializer.validated_data['membership']
        membership.group_admin = serializer.validated_data['group_admin']
        membership.save()

        return Response(status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a group membership

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
