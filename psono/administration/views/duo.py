from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import (
    DeleteDuoSerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Duo, User


class DuoView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    serializer_class = DeleteDuoSerializer
    allowed_methods = ('DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'DELETE':
            return DeleteDuoSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a Duo authenticator
        """

        serializer = DeleteDuoSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        duo = serializer.validated_data.get('duo')

        user_id = duo.user_id

        # delete it
        duo.delete()

        if not Duo.objects.filter(user_id=user_id, active=True).exists():
            user = User.objects.get(pk=user_id)
            user.duo_enabled = False
            user.save()

        return Response({}, status=status.HTTP_200_OK)
