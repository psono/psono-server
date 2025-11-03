from django.utils import timezone
from rest_framework import serializers
import logging
from ..models import DeviceCode

logger = logging.getLogger(__name__)

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

        if device_code.state == device_code.DeviceCodeState.FAILED:
            raise serializers.ValidationError("DEVICE_CODE_INVALID_STATE")

        current_time = timezone.now()
        
        # Check if the code should be expired based on valid_till
        if device_code.valid_till < current_time:
            device_code.delete()
            raise serializers.ValidationError("DEVICE_CODE_EXPIRED")
        
        # Check current state - only CLAIMED codes can proceed to token creation
        if device_code.state != device_code.DeviceCodeState.CLAIMED:
            raise serializers.ValidationError("DEVICE_CODE_NOT_CLAIMED")

        # Data integrity check: CLAIMED codes MUST have a user
        # This should never happen in normal operation - indicates a bug or data corruption
        if device_code.user_id is None:
            logger.error(
                f"DATA INTEGRITY ERROR: Device code {device_code.id} is in CLAIMED state "
                f"but has no user_id set. This indicates a bug in the claiming process. "
                f"Device fingerprint: {device_code.device_fingerprint}"
            )
            device_code.state = device_code.DeviceCodeState.FAILED
            device_code.save(update_fields=['state', 'write_date'])
            raise serializers.ValidationError("DEVICE_CODE_INVALID_STATE")
        
        attrs["device_code"] = device_code

        return attrs