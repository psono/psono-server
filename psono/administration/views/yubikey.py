from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from ..app_settings import (
    DeleteYubikeySerializer
)

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import Yubikey_OTP


class YubikeyOTPView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    serializer_class = DeleteYubikeySerializer
    allowed_methods = ('DELETE', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        """
        Deletes a Yubikey token

        :param request:
        :param args:
        :param kwargs:
        :return: 200 / 400
        """

        serializer = DeleteYubikeySerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        yubikey_otp = serializer.validated_data.get('yubikey_otp')

        # delete it
        yubikey_otp.delete()

        if not Yubikey_OTP.objects.filter(user_id=request.user.id, active=True).exists():
            request.user.yubikey_otp_enabled = False

        return Response(status=status.HTTP_200_OK)
