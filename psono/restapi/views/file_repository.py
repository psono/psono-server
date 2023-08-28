from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

import json

from ..utils import calculate_user_rights_on_file_repository

from ..permissions import IsAuthenticated

from ..app_settings import (
    CreateFileRepositorySerializer,
    UpdateFileRepositorySerializer,
    DeleteFileRepositorySerializer,
)
from ..models import (
    File_Repository,
    File_Repository_Right,
    Group_File_Repository_Right,
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

            file_repository_index = {}

            for file_repository_right in File_Repository.objects.filter(
                    file_repository_right__user=request.user,
            ).annotate(
                read=F('file_repository_right__read'),
                write=F('file_repository_right__write'),
                grant=F('file_repository_right__grant'),
                accepted=F('file_repository_right__accepted'),
                file_repository_right_id=F('file_repository_right__id'),
            ):

                file_repository_index[str(file_repository_right.id)] = {
                    'id': str(file_repository_right.id),
                    'title': file_repository_right.title,
                    'type': file_repository_right.type,
                    'active': file_repository_right.active,
                    'read': file_repository_right.read,
                    'write': file_repository_right.write,
                    'grant': file_repository_right.grant,
                    'accepted': file_repository_right.accepted,
                    'file_repository_right_id': str(file_repository_right.file_repository_right_id),
                }

            #for file_repository_right in File_Repository.objects.filter(group_file_repository_right__group__user=request.user).annotate(read=F('group_file_repository_right__read'), write=F('group_file_repository_right__write'), grant=F('group_file_repository_right__grant')):
            for file_repository_right in File_Repository.objects.raw("""SELECT fr.id, fr.title, fr.type, fr.active, gfrr.read, gfrr.write, gfrr.grant
                FROM restapi_file_repository fr
                    JOIN restapi_group_file_repository_right gfrr ON gfrr.file_repository_id = fr.id
                    JOIN restapi_user_group_membership ms ON ms.group_id = gfrr.group_id
                WHERE ms.user_id = %(user_id)s
                    AND ms.accepted = true""", {
                'user_id': request.user.id,
            }):
                if str(file_repository_right.id) in file_repository_index:
                    file_repository_index[str(file_repository_right.id)]['read'] = file_repository_index[str(file_repository_right.id)]['read'] or file_repository_right.read
                    file_repository_index[str(file_repository_right.id)]['write'] = file_repository_index[str(file_repository_right.id)]['write'] or file_repository_right.write
                    file_repository_index[str(file_repository_right.id)]['grant'] = file_repository_index[str(file_repository_right.id)]['grant'] or file_repository_right.grant
                    continue

                file_repository_index[str(file_repository_right.id)] = {
                    'id': str(file_repository_right.id),
                    'title': file_repository_right.title,
                    'type': file_repository_right.type,
                    'active': file_repository_right.active,
                    'read': file_repository_right.read,
                    'write': file_repository_right.write,
                    'grant': file_repository_right.grant,
                    'accepted': True,
                    'file_repository_right_id': None,
                }



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

            return Response({'file_repositories': list(file_repository_index.values())},
                            status=status.HTTP_200_OK)
        else:
            # Returns the specified file_repository if the user has any rights for it

            rights = calculate_user_rights_on_file_repository(
                user_id=request.user.id,
                file_repository_id=file_repository_id,
            )
            try:
                file_repository = File_Repository.objects.get(
                    pk=file_repository_id
                )
            except File_Repository.DoesNotExist:
                return Response({"message": "NO_PERMISSION_OR_NOT_EXIST",
                                 "resource_id": file_repository_id}, status=status.HTTP_400_BAD_REQUEST)

            if not rights['shared']:
                return Response({"message": "NO_PERMISSION_OR_NOT_EXIST",
                                 "resource_id": file_repository_id}, status=status.HTTP_400_BAD_REQUEST)

            response = {
                'id': str(file_repository_id),
                'title': file_repository.title,
                'type': file_repository.type,
                'active': file_repository.active,
                'read': rights['read'],
                'write': rights['write'],
                'grant': rights['grant'],
                'file_repository_rights': [],
                'group_file_repository_rights': [],
            }

            if rights['read']:
                data = json.loads(decrypt_with_db_secret(file_repository.data))
                for key, value in data.items():
                    if key in response:
                        # protect existing keys
                        continue
                    response[key] = value

            if rights['grant']:
                for file_repository_right in File_Repository_Right.objects.filter(file_repository_id=file_repository_id).select_related('user').only('id', 'user__id', 'user__username', 'read', 'write', 'grant', 'accepted').all():
                    response['file_repository_rights'].append({
                        'id': str(file_repository_right.id),
                        'user_id': str(file_repository_right.user.id),
                        'user_username': file_repository_right.user.username,
                        'read': file_repository_right.read,
                        'write': file_repository_right.write,
                        'grant': file_repository_right.grant,
                        'accepted': file_repository_right.accepted,
                    })

            if rights['grant']:
                for file_repository_right in Group_File_Repository_Right.objects.filter(file_repository_id=file_repository_id).select_related('group').only('id', 'group__id', 'group__name', 'read', 'write', 'grant').all():
                    response['group_file_repository_rights'].append({
                        'id': str(file_repository_right.id),
                        'group_id': str(file_repository_right.group.id),
                        'group_name': file_repository_right.group.name,
                        'read': file_repository_right.read,
                        'write': file_repository_right.write,
                        'grant': file_repository_right.grant,
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
