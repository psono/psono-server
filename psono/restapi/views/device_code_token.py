from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.utils import timezone
from datetime import timedelta
import logging
import json
from typing import cast

from ..models import DeviceCode, Token
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import HexEncoder
from nacl.utils import random as nacl_random

from ..utils import decrypt_with_db_secret
from django.conf import settings
from rest_framework.parsers import JSONParser

from ..serializers.poll_device_code_token import PollDeviceCodeTokenSerializer


logger = logging.getLogger(__name__)


class DeviceCodeTokenView(generics.GenericAPIView):
    """
    Handles checking the token status of a device code via POST method.
    Requires a URL parameter `device_code` (uuid).
    Only returns the state without leaking extra information.
    """

    allowed_methods = ['POST', 'OPTIONS']
    parser_classes = [JSONParser]
    permission_classes = [AllowAny]
    authentication_classes = []
    serializer_class = PollDeviceCodeTokenSerializer
    throttle_scope = "device_code_token"


    def post(self, request, *args, **kwargs):
        """
        Checks the state of a pending DeviceCode.
        If CLAIMED and credentials exist, returns them in a nacl.public.Box encrypted payload.
        Otherwise, returns the state to prevent leaking information.
        """
        serializer = cast(PollDeviceCodeTokenSerializer, self.get_serializer(data=request.data))
        
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        
        device_code = cast(DeviceCode, serializer.validated_data.get("device_code"))
        
        new_session_token = self._create_new_session_token(device_code)
        box = self._prepare_encryption_box(device_code)
        response_data = self._create_encrypted_response_data(device_code, box, new_session_token)

        device_code.delete()
        
        return Response(response_data, status=status.HTTP_200_OK)

    
    def _prepare_encryption_box(self, device_code: DeviceCode) -> Box:
        """Prepare the encryption box for secure communication."""

        server_private_key_hex_decrypted = decrypt_with_db_secret(device_code.server_private_key)
        server_private_key_bytes = HexEncoder.decode(server_private_key_hex_decrypted)
        server_private_key_obj = PrivateKey(server_private_key_bytes)

        user_public_key_bytes = HexEncoder.decode(device_code.user_public_key)
        user_public_key_obj = PublicKey(user_public_key_bytes)

        return Box(server_private_key_obj, user_public_key_obj)


    def _create_new_session_token(self, device_code: DeviceCode) -> dict:
        """
        Creates a new session token for the user associated with the given DeviceCode device_code.
        Raises DeviceCodeTokenError if the user is not set on the device_code.
        """
        user = device_code.user
        device_fingerprint = device_code.device_fingerprint
        device_description = device_code.device_description

        new_token = Token(
            user=user,
            active=True,
            valid_till=(timezone.now() + timedelta(seconds=settings.MAX_APP_TOKEN_TIME_VALID)),
            device_description=device_description,
            device_fingerprint=device_fingerprint,
            client_date=device_code.device_date,
            google_authenticator_2fa=user.google_authenticator_enabled,
            yubikey_otp_2fa=user.yubikey_otp_enabled,
            duo_2fa=user.duo_enabled,
            webauthn_2fa=user.webauthn_enabled,
            ivalt_2fa=user.ivalt_enabled,
        )
        new_token.save()

        return {
            "token": new_token.clear_text_key,
            "session_secret_key": new_token.secret_key,
            "token_valid_till": new_token.valid_till.isoformat(),
        }
    
    def _create_encrypted_response_data(self, instance: DeviceCode, box: Box, new_session_token_data: dict) -> dict:
        """Create and return an encrypted response, including the provided session token data."""
        
        payload_data = {
            "id": str(instance.id),
            "state": DeviceCode.DeviceCodeState.CLAIMED.value,
            "token": new_session_token_data["token"],
            "session_secret_key": new_session_token_data["session_secret_key"],
            "token_valid_till": new_session_token_data["token_valid_till"],
            "encrypted_credentials": HexEncoder.encode(instance.encrypted_credentials).decode() if instance.encrypted_credentials else None,
            "encrypted_credentials_nonce": instance.encrypted_credentials_nonce if instance.encrypted_credentials_nonce else None,
        }
        
        payload_json_bytes = json.dumps(payload_data, sort_keys=True).encode('utf-8')
        encryption_nonce_bytes = nacl_random(Box.NONCE_SIZE)
        encrypted_payload_message = box.encrypt(payload_json_bytes, encryption_nonce_bytes)
        
        return {
            "boxed_payload": HexEncoder.encode(encrypted_payload_message.ciphertext).decode(),
            "nonce": HexEncoder.encode(encryption_nonce_bytes).decode(),
        }
        
    def delete(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    def put(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    def get(self, request, *args, **kwargs):
        return Response({}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    


__all__ = [DeviceCodeTokenView]
