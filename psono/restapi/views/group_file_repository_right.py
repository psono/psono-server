from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from ..permissions import IsAuthenticated

from ..app_settings import (
    CreateGroupFileRepositoryRightSerializer,
    UpdateGroupFileRepositoryRightSerializer,
    DeleteGroupFileRepositoryRightSerializer,
)
from ..models import (
    Group_File_Repository_Right
)
from ..authentication import TokenAuthentication

class GroupFileRepositoryRightView(GenericAPIView):

    """
    Manages group file repository rights
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return CreateGroupFileRepositoryRightSerializer
        if self.request.method == 'POST':
            return UpdateGroupFileRepositoryRightSerializer
        if self.request.method == 'DELETE':
            return DeleteGroupFileRepositoryRightSerializer
        return Serializer

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Creates a new group file repository right
        """

        serializer = CreateGroupFileRepositoryRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group_file_repository_right_id = Group_File_Repository_Right.objects.create(
            group_id=serializer.validated_data['group_id'],
            file_repository_id=serializer.validated_data['file_repository_id'],
            read=serializer.validated_data['read'],
            write=serializer.validated_data['write'],
            grant=serializer.validated_data['grant']
        )

        return Response({'group_file_repository_right_id': group_file_repository_right_id.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a file repository right
        """

        serializer = UpdateGroupFileRepositoryRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group_file_repository_right = serializer.validated_data['group_file_repository_right']
        group_file_repository_right.read = serializer.validated_data['read']
        group_file_repository_right.write = serializer.validated_data['write']
        group_file_repository_right.grant = serializer.validated_data['grant']
        group_file_repository_right.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a group file repository right

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteGroupFileRepositoryRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        group_file_repository_right = serializer.validated_data.get('group_file_repository_right')

        # delete it
        group_file_repository_right.delete()

        return Response({}, status=status.HTTP_200_OK)
