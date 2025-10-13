from django.utils import timezone
from rest_framework import serializers

from ..models import DeviceCode

class PollDeviceCodeTokenSerializer(serializers.Serializer):
    """
    Serializer for polling device code token status.
    Only validates device code state and expiration - business logic handled in view.
    """

    def validate(self, attrs):
        device_code_id = self.context["request"].parser_context["kwargs"].get("device_code", None)

        if not device_code_id:
            raise serializers.ValidationError("DEVICE_CODE_MISSING")

        try:
            device_code = DeviceCode.objects.select_related("user").get(id=device_code_id)
        except DeviceCode.DoesNotExist:
            raise serializers.ValidationError("DEVICE_CODE_NOT_FOUND")

        current_time = timezone.now()
        
        # Check if the code should be expired based on valid_till
        if device_code.valid_till < current_time:
            device_code.delete()
            raise serializers.ValidationError("DEVICE_CODE_EXPIRED")
        
        # Check current state - only CLAIMED codes can proceed to token creation
        if device_code.state != device_code.DeviceCodeState.CLAIMED and device_code.user_id is not None:
            raise serializers.ValidationError("DEVICE_CODE_NOT_CLAIMED")
        
        attrs["device_code"] = device_code

        return attrs