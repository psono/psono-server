from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

import json

from ..permissions import IsAuthenticated

from ..app_settings import (
    CreateFileRepositorySerializer,
    UpdateFileRepositorySerializer,
    DeleteFileRepositorySerializer,
)
from ..models import (
    File_Repository,
    File_Repository_User,
)

from ..utils import encrypt_with_db_secret, decrypt_with_db_secret
from ..authentication import TokenAuthentication


class FileRepositoryView(GenericAPIView):
    """
    Check the REST Token and returns a list of all file_repositorys or the specified file_repositorys details
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, file_repository_id=None, *args, **kwargs):
        """
        Returns either a list of all file_repositorys with own access privileges or the members specified file_repository

        :param request:
        :type request:
        :param file_repository_id:
        :type file_repository_id:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 403
        :rtype:
        """

        if not file_repository_id:

            file_repositorys = []

            for file_repository in File_Repository.objects.filter(file_repository_user__user=request.user).annotate(read=F('file_repository_user__read'), write=F('file_repository_user__write'), grant=F('file_repository_user__grant')):
                file_repositorys.append({
                    'id': file_repository.id,
                    'title': file_repository.title,
                    'type': file_repository.type,
                    'active': file_repository.active,
                    'read': file_repository.read,
                    'write': file_repository.write,
                    'grant': file_repository.grant,
                })

            return Response({'file_repositorys': file_repositorys},
                            status=status.HTTP_200_OK)
        else:
            # Returns the specified file_repository if the user has any rights for it
            try:
                file_repository = File_Repository.objects.select_related('file_repository_user').get(id=file_repository_id, file_repository_user__user=request.user, file_repository_user__read=True)
            except File_Repository.DoesNotExist:
                return Response({"message": "You don't have permission to access or it does not exist.",
                                 "resource_id": file_repository_id}, status=status.HTTP_400_BAD_REQUEST)

            data = json.loads(decrypt_with_db_secret(file_repository.data))

            response = {
                'id': file_repository.id,
                'title': file_repository.title,
                'type': file_repository.type,
                'active': file_repository.active,
            }

            for key, value in data.items():
                response[key] = value

            return Response(response,
                            status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Creates an file_repository

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateFileRepositorySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_repository = File_Repository.objects.create(
            title=str(serializer.validated_data.get('title')),
            type=str(serializer.validated_data.get('type')),
            data=encrypt_with_db_secret(json.dumps(serializer.validated_data.get('data'))),
            active=True,
        )

        File_Repository_User.objects.create(
            user=request.user,
            file_repository=file_repository,
        )

        return Response({
            "file_repository_id": file_repository.id,
        }, status=status.HTTP_201_CREATED)

    def post(self, request, *args, **kwargs):
        """
        Updates a file_repository

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = UpdateFileRepositorySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_repository = serializer.validated_data.get('file_repository')

        file_repository.title = serializer.validated_data.get('title')
        file_repository.type = serializer.validated_data.get('type')
        file_repository.data = encrypt_with_db_secret(json.dumps(serializer.validated_data.get('data')))
        file_repository.active = serializer.validated_data.get('active')

        file_repository.save()

        return Response(status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Deletes an file_repository

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteFileRepositorySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_repository = serializer.validated_data.get('file_repository')

        # delete it
        file_repository.delete()

        return Response(status=status.HTTP_200_OK)
