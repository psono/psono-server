from django.db.models import F
from django.conf import settings
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
    File_Repository_Right,
)

from ..utils import encrypt_with_db_secret, decrypt_with_db_secret
from ..authentication import TokenAuthentication


class FileRepositoryView(GenericAPIView):
    """
    Check the REST Token and returns a list of all file_repositories or the specified file_repositories details
    """

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, file_repository_id=None, *args, **kwargs):
        """
        Returns either a list of all file_repositories with own access privileges or the members specified file_repository

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

            file_repositories = []

            for file_repository_right in File_Repository.objects.filter(file_repository_right__user=request.user).annotate(read=F('file_repository_right__read'), write=F('file_repository_right__write'), grant=F('file_repository_right__grant'), accepted=F('file_repository_right__accepted'), file_repository_right_id=F('file_repository_right__id')):
                file_repositories.append({
                    'id': str(file_repository_right.id),
                    'title': file_repository_right.title,
                    'type': file_repository_right.type,
                    'active': file_repository_right.active,
                    'read': file_repository_right.read,
                    'write': file_repository_right.write,
                    'grant': file_repository_right.grant,
                    'accepted': file_repository_right.accepted,
                    'file_repository_right_id': str(file_repository_right.file_repository_right_id),
                })

            # if settings.DEFAULT_FILE_REPOSITORY_ENABLED:
            #     file_repositories.append({
            #         'id': settings.DEFAULT_FILE_REPOSITORY_UUID,
            #         'title': settings.DEFAULT_FILE_REPOSITORY_TITLE,
            #         'type': settings.DEFAULT_FILE_REPOSITORY_TYPE,
            #         'active': True,
            #         'read': False,
            #         'write': False,
            #         'grant': False,
            #     })

            return Response({'file_repositories': file_repositories},
                            status=status.HTTP_200_OK)
        else:
            # Returns the specified file_repository if the user has any rights for it
            try:
                # file_repository = File_Repository.objects.annotate(read=F('file_repository_right__read'), write=F('file_repository_right__write'), grant=F('file_repository_right__grant')).get(id=file_repository_id, file_repository_right__user=request.user, file_repository_right__accepted=True)
                file_repository_right = File_Repository_Right.objects.select_related('file_repository').get(file_repository_id=file_repository_id, user=request.user, accepted=True)
            except File_Repository_Right.DoesNotExist:
                return Response({"message": "NO_PERMISSION_OR_NOT_EXIST",
                                 "resource_id": file_repository_id}, status=status.HTTP_400_BAD_REQUEST)

            response = {
                'id': str(file_repository_right.file_repository.id),
                'title': file_repository_right.file_repository.title,
                'type': file_repository_right.file_repository.type,
                'active': file_repository_right.file_repository.active,
                'read': file_repository_right.read,
                'write': file_repository_right.write,
                'grant': file_repository_right.grant,
                'file_repository_rights': [],
            }

            if file_repository_right.read:
                data = json.loads(decrypt_with_db_secret(file_repository_right.file_repository.data))
                for key, value in data.items():
                    if key in response:
                        # protect existing keys
                        continue
                    response[key] = value

            if file_repository_right.grant:
                for file_repository_right in File_Repository_Right.objects.filter(file_repository_id=file_repository_right.file_repository_id).select_related('user').only('id', 'user__id', 'user__username', 'read', 'write', 'grant', 'accepted').all():
                    response['file_repository_rights'].append({
                        'id': str(file_repository_right.id),
                        'user_id': str(file_repository_right.user.id),
                        'user_username': file_repository_right.user.username,
                        'read': file_repository_right.read,
                        'write': file_repository_right.write,
                        'grant': file_repository_right.grant,
                        'accepted': file_repository_right.accepted,
                    })

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

        File_Repository_Right.objects.create(
            user=request.user,
            file_repository=file_repository,
            read=True,
            write=True,
            grant=True,
            accepted=True,
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
