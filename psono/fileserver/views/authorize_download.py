from django.db import transaction
from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from restapi.authentication import FileserverAuthentication
from ..permissions import IsFileserver
from ..app_settings import FileserverAuthorizeDownloadSerializer

class AuthorizeDownloadView(GenericAPIView):

    authentication_classes = (FileserverAuthentication, )
    permission_classes = (IsFileserver,)
    allowed_methods = ('PUT', 'OPTIONS', 'HEAD')
    throttle_scope = 'fileserver_download'

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return FileserverAuthorizeDownloadSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Unpacks the authorization information. Checks the user permission (e.g. quota).
        """

        serializer = FileserverAuthorizeDownloadSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_transfer = serializer.validated_data.get('file_transfer')
        hash_checksum = serializer.validated_data.get('hash_checksum')
        file_chunk = serializer.validated_data.get('file_chunk')


        with transaction.atomic():
            file_transfer.size_transferred = F('size_transferred') + file_chunk.size
            file_transfer.chunk_count_transferred = F('chunk_count_transferred') + 1
            file_transfer.save(update_fields=["size_transferred", "chunk_count_transferred", "write_date"])

        return Response({
            'shard_id': file_transfer.shard_id,
            'hash_checksum': hash_checksum,
        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)