from django.db import transaction
from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

import json
import urllib

from ..permissions import IsAuthenticated

from ..app_settings import (
    FileRepositoryDownloadSerializer,
)

from ..utils import (
    decrypt_with_db_secret,
    gcs_construct_signed_download_url,
    aws_construct_signed_download_url,
    azure_blob_construct_signed_download_url,
    do_construct_signed_download_url,
    backblaze_construct_signed_download_url,
    s3_construct_signed_download_url,
)
from ..authentication import FileTransferAuthentication


class FileRepositoryDownloadView(GenericAPIView):

    authentication_classes = (FileTransferAuthentication,)
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('PUT', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return FileRepositoryDownloadSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Creates a signed url for the download of a chunk
        """

        serializer = FileRepositoryDownloadSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_transfer = serializer.validated_data.get('file_transfer')
        file_chunk = serializer.validated_data.get('file_chunk')
        hash_checksum = serializer.validated_data.get('hash_checksum')


        with transaction.atomic():
            file_transfer.size_transferred = F('size_transferred') + file_chunk.size
            file_transfer.chunk_count_transferred = F('chunk_count_transferred') + 1
            file_transfer.save(update_fields=["size_transferred", "chunk_count_transferred", "write_date"])


        data = json.loads(decrypt_with_db_secret(file_transfer.file_repository.data))

        url = ''
        if file_transfer.file_repository.type == 'gcp_cloud_storage':
            base_url, query_params = gcs_construct_signed_download_url(data['gcp_cloud_storage_bucket'], data['gcp_cloud_storage_json_key'], hash_checksum)
            # create an url that contains all the url encoded params
            url = base_url + "?" + urllib.parse.urlencode(query_params)
        if file_transfer.file_repository.type == 'aws_s3':
            url = aws_construct_signed_download_url(data['aws_s3_bucket'], data['aws_s3_region'], data['aws_s3_access_key_id'], data['aws_s3_secret_access_key'], hash_checksum)
        if file_transfer.file_repository.type == 'azure_blob':
            url = azure_blob_construct_signed_download_url(data['azure_blob_storage_account_name'], data['azure_blob_storage_account_primary_key'], data['azure_blob_storage_account_container_name'], hash_checksum)
        if file_transfer.file_repository.type == 'backblaze':
            url = backblaze_construct_signed_download_url(data['backblaze_bucket'], data['backblaze_region'], data['backblaze_access_key_id'], data['backblaze_secret_access_key'], hash_checksum)
        if file_transfer.file_repository.type == 'other_s3':
            url = s3_construct_signed_download_url(data['other_s3_bucket'], data['other_s3_region'], data['other_s3_access_key_id'], data['other_s3_secret_access_key'], hash_checksum, endpoint_url=data['other_s3_endpoint_url'])
        if file_transfer.file_repository.type == 'do_spaces':
            url = do_construct_signed_download_url(data['do_space'], data['do_region'], data['do_key'], data['do_secret'], hash_checksum)

        return Response({
            'type': file_transfer.file_repository.type,
            'url': url
        }, status=status.HTTP_200_OK)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
