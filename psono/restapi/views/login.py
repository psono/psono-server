from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from ..models import (
    Token, Google_Authenticator, Yubikey_OTP
)

from ..app_settings import (
    LoginSerializer
)

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box

# import the logging
import logging
logger = logging.getLogger(__name__)

class LoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    token_model = Token
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Check the credentials and return the REST Token
        if the credentials are valid and authenticated.

        Accepts the following POST parameters: email, authkey
        Returns the token.

        Clients should authenticate by passing the token key in the "Authorization"
        HTTP header, prepended with the string "Token ". For example:

            Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a

        :param request:
        :type request:
        :param args:
        :type args:
        :param kwargs:
        :type kwargs:
        :return:
        :rtype:
        """
        serializer = self.get_serializer(data=self.request.data)

        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.validated_data['user']

        if Google_Authenticator.objects.filter(user=user).exists():
            google_authenticator_2fa = True
        else:
            google_authenticator_2fa = False

        if Yubikey_OTP.objects.filter(user=user).exists():
            yubikey_otp_2fa = True
        else:
            yubikey_otp_2fa = False

        token = self.token_model.objects.create(
            user=user,
            google_authenticator_2fa=google_authenticator_2fa,
            yubikey_otp_2fa=yubikey_otp_2fa,
            device_fingerprint=serializer.validated_data.get('device_fingerprint', ''),
            device_description=serializer.validated_data.get('device_description', ''),
        )

        # our public / private key box
        box = PrivateKey.generate()

        # our hex encoded public / private keys
        server_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        server_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)
        user_session_public_key_hex = serializer.validated_data['user_session_public_key']
        user_public_key_hex = user.public_key

        # both our crypto boxes
        user_crypto_box = Box(PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                              PublicKey(user_public_key_hex, encoder=nacl.encoding.HexEncoder))
        session_crypto_box = Box(PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                                 PublicKey(user_session_public_key_hex, encoder=nacl.encoding.HexEncoder))

        # encrypt session secret with session_crypto_box
        session_secret_key_nonce = nacl.utils.random(Box.NONCE_SIZE)
        session_secret_key_nonce_hex = nacl.encoding.HexEncoder.encode(session_secret_key_nonce)
        encrypted = session_crypto_box.encrypt(token.secret_key, session_secret_key_nonce)
        session_secret_key = encrypted[len(session_secret_key_nonce):]
        session_secret_key_hex = nacl.encoding.HexEncoder.encode(session_secret_key)



        # encrypt user_validator with user_crypto_box
        user_validator_nonce = nacl.utils.random(Box.NONCE_SIZE)
        user_validator_nonce_hex = nacl.encoding.HexEncoder.encode(user_validator_nonce)
        encrypted = user_crypto_box.encrypt(token.user_validator, user_validator_nonce)
        user_validator = encrypted[len(user_validator_nonce):]
        user_validator_hex = nacl.encoding.HexEncoder.encode(user_validator)

        # if getattr(settings, 'REST_SESSION_LOGIN', True):
        #     login(self.request, user)

        required_multifactors = []

        if token.google_authenticator_2fa:
            required_multifactors.append('google_authenticator_2fa')

        if token.yubikey_otp_2fa:
            required_multifactors.append('yubikey_otp_2fa')

        if settings.LOGGING_AUDIT:
            logger.info({'request_method':request.stream.method, 'request_url':request.stream.path, 'success': 'yes', 'status': 'HTTP_200_OK', 'event': 'LOGIN_STARTED', 'user': user.username}, extra={'audit_log_entry': True})

        return Response({
            "token": token.clear_text_key,
            "required_multifactors": required_multifactors,
            "session_public_key": server_session_public_key_hex,
            "session_secret_key": session_secret_key_hex,
            "session_secret_key_nonce": session_secret_key_nonce_hex,
            "user_validator": user_validator_hex,
            "user_validator_nonce": user_validator_nonce_hex,
            "user": {
                "public_key": user.public_key,
                "private_key": user.private_key,
                "private_key_nonce": user.private_key_nonce,
                "user_sauce": user.user_sauce
            }
        },status=status.HTTP_200_OK)

    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)