from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..app_settings import (
    BulkMoveSecretLinkSerializer,
    BulkDeleteSecretLinkSerializer,
)

from ..models import (
    Secret_Link
)

from ..authentication import TokenAuthentication


class BulkSecretLinkView(GenericAPIView):
    """
    Bulk Secret Link View:

    Accepted Methods: POST, DELETE
    """

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'DELETE', 'OPTIONS', 'HEAD')

    def post(self, request, *args, **kwargs):
        """
        Move Secret_Link obj

        Necessary Rights:
            - write on old_parent_share
            - write on old_datastore
            - write on new_parent_share
            - write on new_datastore

        :param request:
        :param uuid:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = BulkMoveSecretLinkSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        link_ids = serializer.validated_data['link_ids']
        new_parent_share_id = serializer.validated_data['new_parent_share_id']
        new_parent_datastore_id = serializer.validated_data['new_parent_datastore_id']
        secrets = serializer.validated_data['secrets']

        # all checks passed, lets move the links with a delete and create at the new location
        Secret_Link.objects.filter(link_id__in=link_ids).delete()

        secret_links = []
        for index, link_id in enumerate(link_ids):
            for secret_id in secrets[index]:
                secret_links.append(Secret_Link(
                    link_id=link_id,
                    secret_id=secret_id,
                    parent_share_id=new_parent_share_id,
                    parent_datastore_id=new_parent_datastore_id
                ))
        Secret_Link.objects.bulk_create(secret_links, ignore_conflicts=True)

        return Response({}, status=status.HTTP_200_OK)



    def delete(self, request, *args, **kwargs):
        """
        Bulk Delete Secret_Link obj

        Necessary Rights:
            - write on parent_share
            - write on parent_datastore

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = BulkDeleteSecretLinkSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        link_ids = serializer.validated_data['link_ids']

        Secret_Link.objects.filter(link_id__in=link_ids).delete()

        return Response({}, status=status.HTTP_200_OK)
