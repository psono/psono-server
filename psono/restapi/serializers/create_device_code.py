# psono/restapi/serializers/device_code.py
from rest_framework import serializers
import nacl.signing
import nacl.encoding
from nacl.public import PublicKey


class CreateDeviceCodeSerializer(serializers.Serializer):
    # Input fields from the client
    device_fingerprint = serializers.CharField(
        required=True,
        max_length=128,
        min_length=22,
        help_text="Unique fingerprint identifier for the initiating device.",
    )
    device_description = serializers.CharField(
        required=True,
        max_length=256,
        min_length=3,
        help_text="Description of the initiating device.",
    )
    device_date = serializers.DateTimeField(
        required=True, help_text="Device timestamp in ISO format."
    )
    user_public_key = serializers.CharField(
        required=True,
        max_length=128,
        help_text="Hex-encoded public key of the initiating user/device.",
    )
    client_type = serializers.CharField(
        required=False,
        default="app",
        allow_null=True,
        max_length=64,
        help_text="Initiating client type, as in normal login; omitted or null defaults to app.",
    )
    session_duration = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=1,
        max_value=2147483647,
        help_text="Requested session duration in seconds; omitted or null uses the client type's default.",
    )

    def validate_user_public_key(self, value):
        """Basic validation for the public key hex string."""
        try:
            _ = PublicKey(value, encoder=nacl.encoding.HexEncoder)
        except Exception:
            raise serializers.ValidationError("INVALID_USER_PUBLIC_KEY")

        return value
