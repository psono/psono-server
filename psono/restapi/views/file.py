from django.db import transaction
from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated

from decimal import Decimal

from ..models import (
    File_Transfer,
    File,
    File_Link,
)

from ..app_settings import (
    CreateFileSerializer,
    ReadFileSerializer,
)
from ..authentication import TokenAuthentication

class FileView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'PUT', 'DELETE', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Indirectly reads a file by providing a filetransfer id for download

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        serializer = ReadFileSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        file = serializer.validated_data['file']
        credit = serializer.validated_data['credit']

        with transaction.atomic():

            file_transfer = File_Transfer.objects.create(
                user_id=request.user.id,
                shard_id=file.shard_id,
                file_repository_id=file.file_repository_id,
                file=file,
                size=file.size,
                size_transferred=0,
                chunk_count=file.chunk_count,
                chunk_count_transferred=0,
                credit=credit,
                type='download',
            )

            if credit != Decimal(str(0)):
                request.user.credit = F('credit') - credit
                request.user.save(update_fields=["credit"])

        return Response({
            "file_transfer_id": file_transfer.id,
        }, status=status.HTTP_201_CREATED)



    def put(self, request, *args, **kwargs):
        """
        Indirectly creats a file by providing a filetransfer id for download

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 201 / 400
        :rtype:
        """

        serializer = CreateFileSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        shard = serializer.validated_data['shard']
        file_repository = serializer.validated_data['file_repository']
        chunk_count = serializer.validated_data['chunk_count']
        size = serializer.validated_data['size']
        link_id = serializer.validated_data['link_id']
        parent_datastore_id = serializer.validated_data['parent_datastore_id']
        parent_share_id = serializer.validated_data['parent_share_id']
        credit = serializer.validated_data['credit']

        size_transferred = 0
        chunk_count_transferred = 0

        with transaction.atomic():
            file = File.objects.create(
                shard = shard,
                file_repository = file_repository,
                chunk_count = chunk_count,
                size = size,
                user_id = request.user.id,
            )

            file_transfer = File_Transfer.objects.create(
                user_id=request.user.id,
                shard=shard,
                file_repository=file_repository,
                file=file,
                size=size,
                size_transferred=size_transferred,
                chunk_count=chunk_count,
                chunk_count_transferred=chunk_count_transferred,
                credit=credit,
                type='upload',
            )

            File_Link.objects.create(
                link_id = link_id,
                file_id = file.id,
                parent_datastore_id = parent_datastore_id,
                parent_share_id = parent_share_id
            )

            if credit != Decimal(str(0)):
                request.user.credit = F('credit') - credit
                request.user.save(update_fields=["credit"])

        return Response({
            "file_id": file.id,
            "file_transfer_id": file_transfer.id
        }, status=status.HTTP_201_CREATED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
