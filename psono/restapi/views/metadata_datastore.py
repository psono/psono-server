from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..app_settings import (
    ReadMetadataDatastoreSerializer,
)

from ..authentication import TokenAuthentication
from ..models import Secret_Link
from ..models import Share_Tree

class MetadataDatastoreView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get(self, request, *args, **kwargs):
        """
        Returns the metadata info for a specific datastore

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """

        serializer = ReadMetadataDatastoreSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        datastore = serializer.validated_data.get('datastore')

        secrets = []
        for secret_link in Secret_Link.objects.select_related('secret').only('secret_id', 'secret__write_date').filter(parent_datastore_id=datastore.id):
            secrets.append({
                'id': secret_link.secret_id,
                'write_date': secret_link.secret.write_date.isoformat(),
            })

        shares = []
        for share_tree_entry in Share_Tree.objects.select_related('share').only('share_id', 'share__write_date').filter(parent_datastore_id=datastore.id):
            shares.append({
                'id': share_tree_entry.share_id,
                'write_date': share_tree_entry.share.write_date.isoformat(),
            })

        return Response({
            'write_date': datastore.write_date.isoformat(),
            'shares': shares,
            'secrets': secrets,
        }, status=status.HTTP_200_OK)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
