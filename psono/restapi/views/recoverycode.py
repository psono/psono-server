from django.contrib.auth.hashers import make_password

from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated

from ..authentication import TokenAuthentication
from ..app_settings import (
    CreateRecoverycodeSerializer,
)
from ..models import (
    Recovery_Code
)


class RecoveryCodeView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):

        serializer = CreateRecoverycodeSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # delete existing Recovery Codes
        Recovery_Code.objects.filter(user=request.user).delete()

        recovery_code = Recovery_Code.objects.create(
            user = request.user,
            recovery_authkey = make_password(str(serializer.validated_data['recovery_authkey'])),
            recovery_data = serializer.validated_data['recovery_data'].encode(),
            recovery_data_nonce = serializer.validated_data['recovery_data_nonce'],
            recovery_sauce = str(serializer.validated_data['recovery_sauce']),
        )

        return Response({
            'recovery_code_id': recovery_code.id
        }, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
