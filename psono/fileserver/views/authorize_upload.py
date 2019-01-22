from django.db import transaction
from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from restapi.authentication import FileserverAuthentication
from ..permissions import IsFileserver
from ..app_settings import FileserverAuthorizeUploadSerializer
from restapi.models import File_Chunk

class AuthorizeUploadView(GenericAPIView):

    authentication_classes = (FileserverAuthentication, )
    permission_classes = (IsFileserver,)
    allowed_methods = ('PUT', 'OPTIONS', 'HEAD')
    throttle_scope = 'fileserver_upload'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Unpacks the authorization information. Checks the user permission (e.g. quota).

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = FileserverAuthorizeUploadSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_transfer = serializer.validated_data.get('file_transfer')
        user_id = serializer.validated_data.get('user_id')
        chunk_position = serializer.validated_data.get('chunk_position')
        chunk_size = serializer.validated_data.get('chunk_size')
        hash_blake2b = serializer.validated_data.get('hash_blake2b')


        with transaction.atomic():
            File_Chunk.objects.create(
                user_id=user_id,
                file_id=file_transfer.file_id,
                hash_blake2b=hash_blake2b,
                position=chunk_position,
                size=chunk_size,
            )

            file_transfer.size_transferred = F('size_transferred') + chunk_size
            file_transfer.chunk_count_transferred = F('chunk_count_transferred') + 1
            file_transfer.save(update_fields=["size_transferred", "chunk_count_transferred", "write_date"])


        return Response({
            'shard_id': file_transfer.shard_id,
        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)