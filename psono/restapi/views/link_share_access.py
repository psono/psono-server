from django.db import transaction
from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.serializers import Serializer
from rest_framework.parsers import JSONParser

from decimal import Decimal

from ..utils import user_has_rights_on_secret

from ..models import (
    File_Transfer,
)
from ..app_settings import (
    ReadLinkShareAccessSerializer,
    UpdateLinkShareAccessSerializer,
)

class LinkShareAccessView(GenericAPIView):
    """
    Check the REST Token and returns a list of all link_shares or the specified link_shares details
    """

    permission_classes = (AllowAny,)
    allowed_methods = ('PUT', 'POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'link_share_secret'
    parser_classes = [JSONParser]

    def get_serializer_class(self):
        if self.request.method == 'PUT':
            return ReadLinkShareAccessSerializer
        if self.request.method == 'POST':
            return UpdateLinkShareAccessSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        """
        Use a link share to update a secret.
        """

        serializer = UpdateLinkShareAccessSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        link_share = serializer.validated_data.get('link_share')
        secret = serializer.validated_data.get('secret')
        secret_data = serializer.validated_data.get('secret_data')
        secret_data_nonce = serializer.validated_data.get('secret_data_nonce')

        delete_link_share = link_share.allowed_reads is not None and link_share.allowed_reads <= 1

        if delete_link_share:
            link_share.delete()
        elif link_share.allowed_reads is not None:
            link_share.allowed_reads = link_share.allowed_reads - 1
            link_share.save()

        secret.data = secret_data.encode()
        secret.data_nonce = secret_data_nonce
        secret.save()

        return Response({}, status=status.HTTP_200_OK)


    def post(self, request, *args, **kwargs):
        """
        Use a link share to access a secret.
        """

        serializer = ReadLinkShareAccessSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        link_share = serializer.validated_data.get('link_share')
        secret = serializer.validated_data.get('secret')
        file = serializer.validated_data.get('file')
        credit = serializer.validated_data.get('credit')
        shards = serializer.validated_data.get('shards')

        node = link_share.node.decode()
        node_nonce = link_share.node_nonce
        user = link_share.user

        allow_write = link_share.allow_write

        if allow_write and link_share.secret_id is not None and not user_has_rights_on_secret(link_share.user_id, link_share.secret_id, write=True):
            allow_write = False

        delete_link_share = not allow_write and link_share.allowed_reads is not None and link_share.allowed_reads <= 1

        if delete_link_share:
            link_share.delete()
        elif link_share.allowed_reads is not None:
            if not allow_write:
                link_share.allowed_reads = link_share.allowed_reads - 1
                link_share.save()

        if secret:
            read_count = secret.read_count
            secret.read_count = F('read_count') + 1
            secret.save(update_fields=["read_count"])

            return Response({
                'node': node,
                'node_nonce': node_nonce,
                'secret_data': secret.data.decode(),
                'secret_data_nonce': secret.data_nonce,
                'secret_read_count': read_count + 1,
                'allow_write': allow_write,
            }, status=status.HTTP_200_OK)

        if file:
            with transaction.atomic():

                file_transfer = File_Transfer.objects.create(
                    user_id=user.id,
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
                    user.credit = F('credit') - credit
                    user.save(update_fields=["credit"])

            return Response({
                "file_transfer_id": file_transfer.id,
                "file_transfer_secret_key": file_transfer.secret_key,
                "shards": shards,
                'node': node,
                'node_nonce': node_nonce,
                'allow_write': False,
            }, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
