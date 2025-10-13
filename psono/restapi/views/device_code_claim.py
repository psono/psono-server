from typing import cast
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from ..models import DeviceCode
from ..serializers.claim_device_code import ClaimDeviceCodeSerializer, DeviceCodeExpiredError
from ..authentication import TokenAuthentication

class DeviceCodeClaimView(GenericAPIView):
    """
    Handles the claiming of Device Codes via PUT method.
    Requires a URL parameter `device_code` (uuid) and authentication.
    """

    queryset = DeviceCode.objects.all()
    lookup_url_kwarg = 'device_code'
    http_method_names = ['put', 'options']
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    serializer_class = ClaimDeviceCodeSerializer

    def put(self, request, *args, **kwargs):
        """
        Claims a pending DeviceCode by associating the authenticated user
        and storing encrypted credentials. Requires authentication.
        Expects 'device_code' in the URL.
        """
        instance = self.get_object()
        
        serializer = cast(ClaimDeviceCodeSerializer, self.get_serializer(instance, data=request.data, context={'user': request.user}))

        try:
            if not serializer.is_valid():
                return Response(
                    serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )
        except DeviceCodeExpiredError:
            instance.state = DeviceCode.DeviceCodeState.EXPIRED
            instance.save(update_fields=['state', 'write_date'])
            
            raise

        validated_data = serializer.validated_data
        
        credentials_bytes = validated_data.get('_credentials_bytes')
        
        instance.encrypted_credentials = credentials_bytes
        instance.encrypted_credentials_nonce = validated_data.get('encrypted_credentials_nonce', '')
        instance.user = request.user
        instance.state = DeviceCode.DeviceCodeState.CLAIMED
        instance.save(update_fields=['encrypted_credentials', 'encrypted_credentials_nonce', 'user', 'state', 'write_date'])

        response_body = {
            "state": instance.state.value,
            "user": instance.user.id,
            "server_public_key": instance.server_public_key,
            "user_public_key": instance.user_public_key,
            "encrypted_credentials": serializer.get_encrypted_credentials(instance),
            "encrypted_credentials_nonce": instance.encrypted_credentials_nonce,
        }

        return Response(response_body, status=status.HTTP_200_OK) 
    
    def http_method_not_allowed(self, request, *args, **kwargs):
        """
        If a method other than PUT is called, return a clear error message.
        """
        return Response(
            {"detail": f"{request.method.upper()} method not supported. Use PUT to claim a device code."},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )