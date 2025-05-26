from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer

import nacl.encoding
import json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
from webauthn.helpers.structs import UserVerificationRequirement
from webauthn import (
    generate_authentication_options,
    options_to_json,
)

from ..utils import encrypt_with_db_secret
from ..permissions import IsAuthenticated
from ..models import (
    Token,
    Webauthn,
)

from ..app_settings import (
    WebauthnVerifyInitSerializer,
    WebauthnVerifySerializer,
)
from ..authentication import TokenAuthenticationAllowInactive

class WebauthnVerifyView(GenericAPIView):

    authentication_classes = (TokenAuthenticationAllowInactive, )
    permission_classes = (IsAuthenticated,)
    token_model = Token
    allowed_methods = ('POST', 'PUT', 'OPTIONS', 'HEAD')
    throttle_scope = 'duo_verify'

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return WebauthnVerifySerializer
        if self.request.method == 'PUT':
            return WebauthnVerifyInitSerializer
        return Serializer

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, request, *args, **kwargs):

        serializer = WebauthnVerifyInitSerializer(data=request.data, context=self.get_serializer_context())

        if not serializer.is_valid():

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        origin = serializer.validated_data.get('origin')
        rp_id = serializer.validated_data.get('rp_id')

        allow_credentials = []
        webauthns = Webauthn.objects.filter(user_id=request.user.id, origin=origin, active=True).only('credential_id')
        for w in webauthns:
            allow_credentials.append(PublicKeyCredentialDescriptor(id=nacl.encoding.HexEncoder.decode(w.credential_id)))

        opts = generate_authentication_options(
            rp_id=rp_id,
            timeout=90000,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.DISCOURAGED
        )
        options = json.loads(options_to_json(opts))

        Webauthn.objects.filter(user_id=request.user.id, origin=origin, active=True).update(challenge=encrypt_with_db_secret(options['challenge']))

        return Response({
            "options": options
        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        Validates a Webauthn (if provided) or returns once the push message on the phone has been confirmed

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
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        # Webauthn challenge has been solved, so lets update the token
        token = serializer.validated_data['token']
        token.webauthn_2fa = False

        if settings.MULTIFACTOR_ENABLED:
            # only mark webauthn challenge as solved and the others potentially open
            token.webauthn_2fa = False
        else:
            token.google_authenticator_2fa = False
            token.yubikey_otp_2fa = False
            token.duo_2fa = False
            token.webauthn_2fa = False
            token.ivalt_2fa = False

        token.save()

        return Response({}, status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)