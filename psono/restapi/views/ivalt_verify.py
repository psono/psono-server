from rest_framework import status
from django.conf import settings
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from ..permissions import IsAuthenticated
from ..models import (
    Token
)

from ..app_settings import (
    IvaltVerifySerializer
)
from ..authentication import TokenAuthenticationAllowInactive

class IvaltVerifyView(GenericAPIView):
    authentication_classes = (TokenAuthenticationAllowInactive, )
    permission_classes = (IsAuthenticated,)
    serializer_class = IvaltVerifySerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'ivalt_verify'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Validates a Ivalt 2fa based on mobile auth validation

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return: 200 / 400
        :rtype:
        """

        serializer = self.get_serializer(data=self.request.data)

        if not serializer.is_valid():
            if isinstance(serializer.errors, dict):
                errors = {key: value[0] for key, value in serializer.errors.items()}
            else:
                errors = serializer.errors
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        
        request_type = serializer.validated_data['request_type']
        if request_type == 'verification':
            token = serializer.validated_data['token']
            if settings.MULTIFACTOR_ENABLED:
                # only mark iVALT challenge as solved and the others potentially open
                token.ivalt_2fa = False
            else:
                token.ivalt_2fa = False
                token.google_authenticator_2fa = False
                token.yubikey_otp_2fa = False
                token.duo_2fa = False
                token.webauthn_2fa = False

            token.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)