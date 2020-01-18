from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny

import nacl.encoding
import nacl.utils
import nacl.secret
import nacl.signing
from nacl.public import PrivateKey, PublicKey, Box

from datetime import timedelta
import json
import binascii

from ..models import (
    Token
)
from ..app_settings import (
    APIKeyLoginSerializer
)

class APIKeyLoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = APIKeyLoginSerializer
    allowed_methods = ('POST', 'OPTIONS', 'HEAD')
    throttle_scope = 'login'

    def get(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def put(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request, *args, **kwargs):
        """
        Check the api key and return the REST Token if its valid.

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

        api_key = serializer.validated_data['api_key']

        if not settings.ALLOW_MULTIPLE_SESSIONS:
            Token.objects.filter(user=api_key.user).delete()

        token = Token.objects.create(
            user=api_key.user,
            google_authenticator_2fa=False,
            duo_2fa=False,
            yubikey_otp_2fa=False,
            device_fingerprint=serializer.validated_data.get('device_fingerprint', ''),
            device_description=serializer.validated_data.get('device_description', ''),
            client_date=serializer.validated_data.get('device_time'),
            valid_till=timezone.now() + timedelta(seconds=serializer.validated_data.get('session_duration')),
            active=True,
            read=api_key.read,
            write=api_key.write,
        )

        # our public / private key box
        box = PrivateKey.generate()

        # our hex encoded public / private keyssession_duration
        server_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        server_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)
        user_session_public_key_hex = serializer.validated_data['user_session_public_key']

        response = {
            "token": token.clear_text_key,
            "session_secret_key": token.secret_key,
            "api_key_restrict_to_secrets": api_key.restrict_to_secrets,
            "api_key_allow_insecure_access": api_key.allow_insecure_access,
            "api_key_read": api_key.read,
            "api_key_write": api_key.write,
            "user": {
                "username": api_key.user.username,
                "public_key": api_key.user.public_key,
            }
        }

        if not api_key.restrict_to_secrets:
            response['user']['private_key'] = api_key.user_private_key
            response['user']['private_key_nonce'] = api_key.user_private_key_nonce
            response['user']['secret_key'] = api_key.user_secret_key
            response['user']['secret_key_nonce'] = api_key.user_secret_key_nonce

        server_crypto_box = Box(PrivateKey(server_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                                PublicKey(user_session_public_key_hex, encoder=nacl.encoding.HexEncoder))

        login_info_nonce = nacl.utils.random(Box.NONCE_SIZE)
        login_info_nonce_hex = nacl.encoding.HexEncoder.encode(login_info_nonce)
        encrypted = server_crypto_box.encrypt(json.dumps(response).encode(), login_info_nonce)
        encrypted_login_info = encrypted[len(login_info_nonce):]
        encrypted_login_info_hex = nacl.encoding.HexEncoder.encode(encrypted_login_info)

        signing_box = nacl.signing.SigningKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder)

        # The first 128 chars (512 bits or 64 bytes) are the actual signature, the rest the binary encoded info
        signed = signing_box.sign(encrypted_login_info_hex)
        signature = binascii.hexlify(signed.signature)

        return Response({
            'login_info': encrypted_login_info_hex,
            'login_info_signature': signature,
            'login_info_nonce': login_info_nonce_hex,
            'server_session_public_key': server_session_public_key_hex.decode('utf-8')
        },status=status.HTTP_200_OK)



    def delete(self, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)