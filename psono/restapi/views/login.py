from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box

from datetime import timedelta
import json

from ..models import (
    Token, Ivalt
)
from ..app_settings import (
    LoginSerializer
)

class LoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'login'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Check the username and authkey and return the REST Token
        if the credentials are valid and authenticated.

        Clients should later authenticate by passing the token key in the "Authorization"
        HTTP header, prepended with the string "Token ". For example:

            Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a

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

        user = serializer.validated_data['user']

        if not settings.ALLOW_MULTIPLE_SESSIONS:
            Token.objects.filter(user=user).delete()

        token = Token.objects.create(
            user=user,
            google_authenticator_2fa=user.google_authenticator_enabled,
            duo_2fa=user.duo_enabled,
            webauthn_2fa=user.webauthn_enabled,
            yubikey_otp_2fa=user.yubikey_otp_enabled,
            ivalt_2fa=user.ivalt_enabled,
            device_fingerprint=serializer.validated_data.get('device_fingerprint', ''),
            device_description=serializer.validated_data.get('device_description', ''),
            client_date=serializer.validated_data.get('device_time'),
            valid_till=timezone.now() + timedelta(seconds=serializer.validated_data.get('session_duration')),
            read=True,
            write=True,
        )

        # our public / private key box
        box = PrivateKey.generate()

        # our hex encoded public / private keyssession_duration
        server_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        server_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)
        user_session_public_key_hex = serializer.validated_data['user_session_public_key']
        user_public_key_hex = user.public_key

        # encrypt session secret with session_crypto_box
        session_crypto_box = Box(PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                                 PublicKey(user_session_public_key_hex, encoder=nacl.encoding.HexEncoder))
        session_secret_key_nonce = nacl.utils.random(Box.NONCE_SIZE)
        session_secret_key_nonce_hex = nacl.encoding.HexEncoder.encode(session_secret_key_nonce)
        encrypted = session_crypto_box.encrypt(token.secret_key.encode(), session_secret_key_nonce)
        session_secret_key = encrypted[len(session_secret_key_nonce):]
        session_secret_key_hex = nacl.encoding.HexEncoder.encode(session_secret_key)

        # encrypt user_validator with user_crypto_box
        user_crypto_box = Box(PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                              PublicKey(user_public_key_hex, encoder=nacl.encoding.HexEncoder))
        user_validator_nonce = nacl.utils.random(Box.NONCE_SIZE)
        user_validator_nonce_hex = nacl.encoding.HexEncoder.encode(user_validator_nonce)
        encrypted = user_crypto_box.encrypt(token.user_validator.encode(), user_validator_nonce)
        user_validator = encrypted[len(user_validator_nonce):]
        user_validator_hex = nacl.encoding.HexEncoder.encode(user_validator)

        # if getattr(settings, 'REST_SESSION_LOGIN', True):
        #     login(self.request, user)

        required_multifactors = []

        if user.google_authenticator_enabled:
            required_multifactors.append('google_authenticator_2fa')

        if user.duo_enabled:
            required_multifactors.append('duo_2fa')

        if user.yubikey_otp_enabled:
            required_multifactors.append('yubikey_otp_2fa')

        if user.webauthn_enabled:
            required_multifactors.append('webauthn_2fa')

        if user.ivalt_enabled:
            required_multifactors.append('ivalt_2fa')

        response = {
            "token": token.clear_text_key,
            "session_valid_till": token.valid_till.isoformat(),
            "required_multifactors": required_multifactors,
            "session_public_key": server_session_public_key_hex.decode('utf-8'),
            "session_secret_key": session_secret_key_hex.decode('utf-8'),
            "session_secret_key_nonce": session_secret_key_nonce_hex.decode('utf-8'),
            "user_validator": user_validator_hex.decode('utf-8'),
            "user_validator_nonce": user_validator_nonce_hex.decode('utf-8'),
            "user": {
                "username": user.username,
                "language": user.language,
                "public_key": user.public_key,
                "private_key": user.private_key,
                "private_key_nonce": user.private_key_nonce,
                "user_sauce": user.user_sauce,
                "authentication": user.authentication,
                'hashing_algorithm': user.hashing_algorithm,
                'hashing_parameters': user.hashing_parameters,
            }
        }

        server_crypto_box = Box(PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
                                PublicKey(user_session_public_key_hex, encoder=nacl.encoding.HexEncoder))

        login_info_nonce = nacl.utils.random(Box.NONCE_SIZE)
        login_info_nonce_hex = nacl.encoding.HexEncoder.encode(login_info_nonce)
        encrypted = server_crypto_box.encrypt(json.dumps(response).encode(), login_info_nonce)
        encrypted_login_info = encrypted[len(login_info_nonce):]
        encrypted_login_info_hex = nacl.encoding.HexEncoder.encode(encrypted_login_info)

        return Response({
            'login_info': encrypted_login_info_hex,
            'login_info_nonce': login_info_nonce_hex
        },status=status.HTTP_200_OK)



    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)