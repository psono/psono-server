from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

from ..permissions import AdminPermission
from restapi.authentication import TokenAuthentication
from restapi.models import User


class StatsTwoFactorView(GenericAPIView):

    authentication_classes = (TokenAuthentication, )
    permission_classes = (AdminPermission,)
    allowed_methods = ('GET', 'OPTIONS', 'HEAD')

    def get_serializer_class(self):
        return Serializer

    def get(self, request, *args, **kwargs):
        """
        Returns the statistics of used two factors
        """

        user_count = User.objects.count()
        user_google_authenticator_enabled_count = User.objects.filter(google_authenticator_enabled=True).count()
        user_duo_enabled_count = User.objects.filter(duo_enabled=True).count()
        user_webauthn_enabled_count = User.objects.filter(webauthn_enabled=True).count()
        user_yubikey_otp_enabled_count = User.objects.filter(yubikey_otp_enabled=True).count()

        return Response({
            'users': user_count,
            'user_google_authenticator_enabled_count': user_google_authenticator_enabled_count,
            'user_duo_enabled_count': user_duo_enabled_count,
            'user_webauthn_enabled_count': user_webauthn_enabled_count,
            'user_yubikey_otp_enabled_count': user_yubikey_otp_enabled_count,
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def delete(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
