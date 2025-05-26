from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from  more_itertools import unique_everseen

import json

from ..permissions import IsAuthenticated
from ..utils import decrypt_with_db_secret, gcs_delete, aws_delete, azure_blob_delete, do_delete, backblaze_delete, s3_delete
from ..utils import is_allowed_other_s3_endpoint_url

from ..app_settings import (
    MoveFileLinkSerializer,
    DeleteFileLinkSerializer,
)

from ..models import (
    File_Link,
    File,
)

from ..authentication import TokenAuthentication

def create_file_link(link_id, file_id, parent_share_id, parent_datastore_id):
    """
    DB wrapper to create a link between a file and a datastore or a share

    Takes care of "degenerated" tree structures (e.g a child has two parents)

    In addition checks if the link already exists, as this is a crucial part of the access rights system

    :param link_id:
    :param file_id:
    :param parent_share_id:
    :param parent_datastore_id:
    :return:
    """

    try:
        File_Link.objects.create(
            link_id = link_id,
            file_id = file_id,
            parent_datastore_id = parent_datastore_id,
            parent_share_id = parent_share_id
        )
    except:
        return False

    return True


class FileLinkView(GenericAPIView):
    """
    File Link View:

    Accepted Methods: POST, DELETE
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return MoveFileLinkSerializer
        if self.request.method == 'DELETE':
            return DeleteFileLinkSerializer
        return Serializer

    def post(self, request, *args, **kwargs):
        """
        Move File_Link obj

        Necessary Rights:
            - write on old_parent_share
            - write on old_datastore
            - write on new_parent_share
            - write on new_datastore
        """

        serializer = MoveFileLinkSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        link_id = serializer.validated_data['link_id']
        new_parent_share_id = serializer.validated_data['new_parent_share_id']
        new_parent_datastore_id = serializer.validated_data['new_parent_datastore_id']
        files = serializer.validated_data['files']

        # all checks passed, lets move the link with a delete and create at the new location
        File_Link.objects.filter(link_id=link_id).delete()

        for file_id in files:
            create_file_link(link_id, file_id, new_parent_share_id, new_parent_datastore_id)

        return Response({}, status=status.HTTP_200_OK)



    def delete(self, request, *args, **kwargs):
        """
        Delete File_Link obj

        Necessary Rights:
            - write on parent_share
            - write on parent_datastore
        """

        serializer = DeleteFileLinkSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        link_id = serializer.validated_data['link_id']
        file_ids = serializer.validated_data['file_ids']

        with transaction.atomic():
            File_Link.objects.filter(link_id=link_id).delete()

            # Check if links to the files still exist. If not mark the files for deletion.

            file_ids_with_links = File_Link.objects.using('default').filter(file_id__in=file_ids).values_list('file_id', flat=True)
            file_ids_with_links = list(unique_everseen(file_ids_with_links))
            file_ids_deletable = list(set(file_ids).difference(set(file_ids_with_links)))

            File.objects.filter(pk__in=file_ids_deletable, file_repository__isnull=True).update(delete_date=timezone.now())
            for file in File.objects.using('default').filter(pk__in=file_ids_deletable, file_repository__isnull=False):

                data = json.loads(decrypt_with_db_secret(file.file_repository.data))

                file_repository_type = file.file_repository.type
                for c in file.file_chunk.all():
                    if file_repository_type == 'gcp_cloud_storage':
                        gcs_delete(data['gcp_cloud_storage_bucket'], data['gcp_cloud_storage_json_key'], c.hash_checksum)
                    if file_repository_type == 'aws_s3':
                        aws_delete(data['aws_s3_bucket'], data['aws_s3_region'], data['aws_s3_access_key_id'], data['aws_s3_secret_access_key'], c.hash_checksum)
                    if file_repository_type == 'azure_blob':
                        azure_blob_delete(data['azure_blob_storage_account_name'], data['azure_blob_storage_account_primary_key'], data['azure_blob_storage_account_container_name'], c.hash_checksum)
                    if file_repository_type == 'do_spaces':
                        do_delete(data['do_space'], data['do_region'], data['do_key'], data['do_secret'], c.hash_checksum)
                    if file_repository_type == 'backblaze':
                        backblaze_delete(data['backblaze_bucket'], data['backblaze_region'], data['backblaze_access_key_id'], data['backblaze_secret_access_key'], c.hash_checksum)
                    if file_repository_type == 'other_s3' and is_allowed_other_s3_endpoint_url(data['other_s3_endpoint_url']):
                        s3_delete(data['other_s3_bucket'], data['other_s3_region'], data['other_s3_access_key_id'], data['other_s3_secret_access_key'], c.hash_checksum, endpoint_url=data['other_s3_endpoint_url'])

            File.objects.filter(pk__in=file_ids_deletable, file_repository__isnull=False).delete()

        return Response({}, status=status.HTTP_200_OK)