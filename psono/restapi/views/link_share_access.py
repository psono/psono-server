from django.db import transaction
from django.db.models import F
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny

from decimal import Decimal

from ..models import (
    File_Transfer,
)
from ..app_settings import (
    LinkShareAccessSerializer,
)

class LinkShareAccessView(GenericAPIView):
    """
    Check the REST Token and returns a list of all link_shares or the specified link_shares details
    """

    permission_classes = (AllowAny,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'link_share_secret'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Use a link share to access a secret.

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = LinkShareAccessSerializer(data=request.data, context=self.get_serializer_context())

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

        delete_link_share = link_share.allowed_reads is not None and link_share.allowed_reads <= 1

        if delete_link_share:
            link_share.delete()
        elif link_share.allowed_reads is not None:
            link_share.allowed_reads = link_share.allowed_reads - 1
            link_share.save()

        if secret:
            return Response({
                'node': node,
                'node_nonce': node_nonce,
                'secret_data': secret.data.decode(),
                'secret_data_nonce': secret.data_nonce,
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
            }, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
