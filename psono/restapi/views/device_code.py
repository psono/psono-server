import datetime

from django.conf import settings
from django.utils import timezone

from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.parsers import JSONParser

import nacl.signing
import nacl.encoding
from nacl.public import PrivateKey

from ..models import DeviceCode
from ..serializers.create_device_code import CreateDeviceCodeSerializer
from ..utils import encrypt_with_db_secret


class DeviceCodeView(generics.GenericAPIView):
    """
    Handles the creation (POST) of Device Codes.
    """

    http_method_names = ['post', 'options']
    parser_classes = [JSONParser]
    permission_classes = [AllowAny]
    authentication_classes = []
    serializer_class = CreateDeviceCodeSerializer

    def post(self, request, *args, **kwargs):
        """
        Creates a new DeviceCode record. Anonymous access allowed.
        """
        serializer = self.get_serializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
            
        # Get validated data from serializer
        validated_data = serializer.validated_data
        
        device_fingerprint = validated_data['device_fingerprint']
        device_description = validated_data['device_description']
        device_date = validated_data['device_date']
        user_public_key_hex = validated_data['user_public_key']
        
        # Generate server key pair
        server_private_key = PrivateKey.generate()
        server_private_key_hex = server_private_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        server_private_key_hex_encrypted = encrypt_with_db_secret(server_private_key_hex)
        server_public_key_hex = server_private_key.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        
        # Calculate validity period
        valid_duration = datetime.timedelta(seconds=300)  # 5 minutes
        valid_till = timezone.now() + valid_duration
        
        # Create the DeviceCode object
        device_code = DeviceCode.objects.create(
            device_fingerprint=device_fingerprint,
            device_description=device_description,
            device_date=device_date,
            valid_till=valid_till,
            state=DeviceCode.DeviceCodeState.PENDING,
            server_private_key=server_private_key_hex_encrypted,
            server_public_key=server_public_key_hex,
            user_public_key=user_public_key_hex,
        )

        response_body = {
            "id": device_code.id,
            "state": device_code.state,
            "valid_till": device_code.valid_till,
            "server_public_key": device_code.server_public_key,
            "web_client_url": settings.WEB_CLIENT_URL,
        }

        return Response(response_body, status=status.HTTP_201_CREATED)

    def http_method_not_allowed(self, request, *args, **kwargs):
        """
        If a method other than POST is called, return a clear error message.
        """
        return Response(
            {"detail": f"{request.method.upper()} method not supported. Use POST to create a new device code."},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )
