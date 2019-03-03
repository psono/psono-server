from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from django.core.cache import cache
from django.conf import settings

from ..app_settings import (
    CreateFileRepositoryRightSerializer,
    UpdateFileRepositoryRightSerializer,
    DeleteFileRepositoryRightSerializer,
)
from ..models import (
    User_Group_Membership
)
from ..authentication import TokenAuthentication

class FileRepositoryRightView(GenericAPIView):

    """
    Manages file repository rights
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



    def put(self, request, *args, **kwargs):
        """
        Creates a new file repository right

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateFileRepositoryRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_repository_right = User_Group_Membership.objects.create(
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
            share_admin = serializer.validated_data['share_admin'],
        )

        if settings.CACHE_ENABLE:
            cache_key = 'psono_user_status_' + str(serializer.validated_data['user_id'])
            cache.delete(cache_key)

        return Response({'file_repository_right_id': file_repository_right.id}, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a group file repository right

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        serializer = UpdateFileRepositoryRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_repository_right = serializer.validated_data['file_repository_right']
        file_repository_right.group_admin = serializer.validated_data['group_admin']
        file_repository_right.share_admin = serializer.validated_data['share_admin']
        file_repository_right.save()

        return Response(status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a group file repository right

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteFileRepositoryRightSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_repository_right = serializer.validated_data.get('file_repository_right')

        # delete it
        file_repository_right.delete()

        return Response(status=status.HTTP_200_OK)
