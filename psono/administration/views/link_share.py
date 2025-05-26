from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import (
    DeleteLinkShareSerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication


class LinkShareView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    serializer_class = DeleteLinkShareSerializer
    allowed_methods = ('DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'DELETE':
            return DeleteLinkShareSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a Link Share
        """

        serializer = DeleteLinkShareSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        link_share = serializer.validated_data.get('link_share')

        # delete it
        link_share.delete()

        return Response({}, status=status.HTTP_200_OK)
