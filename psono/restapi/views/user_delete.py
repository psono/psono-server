from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..permissions import IsAuthenticated
from ..utils.avatar import delete_avatar_storage_of_user
from ..app_settings import (
    UserDeleteSerializer
)

from ..authentication import TokenAuthentication



class UserDelete(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('DELETE', 'OPTIONS', 'HEAD')
    throttle_scope = 'user_delete'

    def get_serializer_class(self):
        if self.request.method == 'DELETE':
            return UserDeleteSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Checks the REST Token and deletes the current user
        """

        serializer = UserDeleteSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        delete_avatar_storage_of_user(request.user.id)

        # delete it
        request.user.delete()

        return Response({}, status=status.HTTP_200_OK)
