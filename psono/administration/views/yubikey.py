from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..app_settings import (
    DeleteYubikeySerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Yubikey_OTP, User


class YubikeyOTPView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    serializer_class = DeleteYubikeySerializer
    allowed_methods = ('DELETE', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        if self.request.method == 'DELETE':
            return DeleteYubikeySerializer
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

        serializer = DeleteYubikeySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        yubikey_otp = serializer.validated_data.get('yubikey_otp')

        user_id = yubikey_otp.user_id

        # delete it
        yubikey_otp.delete()

        if not Yubikey_OTP.objects.filter(user_id=user_id, active=True).exists():
            user = User.objects.get(pk=user_id)
            user.yubikey_otp_enabled = False
            user.save()

        return Response({}, status=status.HTTP_200_OK)
