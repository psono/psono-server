from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..authentication import TokenAuthentication

from ..app_settings import (
    FileRepositoryRightAcceptSerializer,
)

class FileRepositoryRightAcceptView(GenericAPIView):

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Marks a FileRepositoryRight as accepted.

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = FileRepositoryRightAcceptSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        file_repository_right_obj = serializer.validated_data.get('file_repository_right_obj')

        file_repository_right_obj.accepted = True
        file_repository_right_obj.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


