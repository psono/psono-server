# psono/restapi/serializers/device_code.py
from rest_framework import serializers
import nacl.signing
import nacl.encoding
from nacl.public import PublicKey

class CreateDeviceCodeSerializer(serializers.Serializer):
    # Input fields from the client
    device_fingerprint = serializers.CharField(required=True, max_length=128, min_length=22, help_text="Unique fingerprint identifier for the initiating device.")
    device_description = serializers.CharField(required=True, max_length=256, min_length=3, help_text="Description of the initiating device.")
    device_date = serializers.DateTimeField(required=True, help_text="Device timestamp in ISO format.")
    user_public_key = serializers.CharField(required=True, max_length=128, help_text="Hex-encoded public key of the initiating user/device.")

    def validate_user_public_key(self, value):
        """ Basic validation for the public key hex string. """
        try:
            _ = PublicKey(value, encoder=nacl.encoding.HexEncoder)
        except Exception:
            raise serializers.ValidationError("INVALID_USER_PUBLIC_KEY")

        return value

