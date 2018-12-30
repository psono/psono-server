from django.db import transaction
from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from restapi.authentication import FileserverAuthentication
from ..permissions import IsFileserver
from ..app_settings import AuthorizeUploadSerializer
from restapi.models import File_Chunk, File_Transfer

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

        serializer = AuthorizeUploadSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file = serializer.validated_data.get('file')
        user_id = serializer.validated_data.get('user_id')
        shard_id = serializer.validated_data.get('shard_id')
        chunk_position = serializer.validated_data.get('chunk_position')
        chunk_size = serializer.validated_data.get('chunk_size')
        hash_blake2b = serializer.validated_data.get('hash_blake2b')


        with transaction.atomic():
            file_chunk = File_Chunk.objects.create(
                user_id=user_id,
                file=file,
                hash_blake2b=hash_blake2b,
                position=chunk_position,
                size=chunk_size,
            )

            File_Transfer.objects.create(
                user_id=user_id,
                file_chunk=file_chunk,
                size=chunk_size,
                type='upload',
            )

            file.chunk_count_uploaded = F('chunk_count_uploaded') + 1
            file.size_uploaded = F('size_uploaded') + chunk_size
            file.save(update_fields=["chunk_count_uploaded", "size_uploaded"])


        return Response({
            'shard_id': shard_id,
        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)