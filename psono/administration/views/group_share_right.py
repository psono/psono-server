from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import (
    UpdateGroupShareRightSerializer,
    DeleteGroupShareRightSerializer,
)
from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Group_Share_Right



class GroupShareRightView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('PUT', 'DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return UpdateGroupShareRightSerializer
        elif self.request.method == 'DELETE':
            return DeleteGroupShareRightSerializer
        return Serializer

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Updates a group share right
        """

        serializer = UpdateGroupShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group_share_right = serializer.validated_data.get('group_share_right')
        read = serializer.validated_data.get('read')
        write = serializer.validated_data.get('write')
        grant = serializer.validated_data.get('grant')

        require_save = False
        if read is not None:
            group_share_right.read = read
            require_save = True
        if write is not None:
            group_share_right.write = write
            require_save = True
        if grant is not None:
            group_share_right.grant = grant
            require_save = True

        if require_save:
            group_share_right.save()

        return Response({}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


    def delete(self, request, *args, **kwargs):
        """
        Deletes a group share right
        """

        serializer = DeleteGroupShareRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group_share_right = serializer.validated_data.get('group_share_right')

        # delete it
        group_share_right.delete()

        return Response({}, status=status.HTTP_200_OK)
