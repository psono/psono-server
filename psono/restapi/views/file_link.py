from django.db import transaction
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from  more_itertools import unique_everseen

from ..permissions import IsAuthenticated

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

            # Check if links to the files still exist. If not delete the files.
            # File.delete() handles both shard (soft-delete) and file repository (hard-delete with cloud cleanup)

            file_ids_with_links = File_Link.objects.using('default').filter(file_id__in=file_ids).values_list('file_id', flat=True)
            file_ids_with_links = list(unique_everseen(file_ids_with_links))
            file_ids_deletable = list(set(file_ids).difference(set(file_ids_with_links)))

            # Delete orphaned files - File.delete() handles all cleanup logic
            for file in File.objects.using('default').filter(pk__in=file_ids_deletable):
                file.delete()

        return Response({}, status=status.HTTP_200_OK)