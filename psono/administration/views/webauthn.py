from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import (
    DeleteWebAuthnSerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Webauthn, User


class WebAuthnView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    serializer_class = DeleteWebAuthnSerializer
    allowed_methods = ('DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'DELETE':
            return DeleteWebAuthnSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a Yubikey token
        """

        serializer = DeleteWebAuthnSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        webauthn = serializer.validated_data.get('webauthn')

        user_id = webauthn.user_id

        # delete it
        webauthn.delete()

        if not Webauthn.objects.filter(user_id=user_id, active=True).exists():
            user = User.objects.get(pk=user_id)
            user.webauthn_enabled = False
            user.save()

        return Response({}, status=status.HTTP_200_OK)
