import re

from django.conf import settings
from django.contrib.auth.hashers import check_password
from rest_framework import exceptions, serializers

from ..hashing import is_weaker_hashing_profile
from ..models import HASHING_ALGORITHMS


class UserUpgradeHashingSerializer(serializers.Serializer):
    """Validate a hashing-parameter upgrade."""

    authkey = serializers.CharField(
        style={"input_type": "password"},
        min_length=settings.AUTH_KEY_LENGTH_BYTES * 2,
        max_length=settings.AUTH_KEY_LENGTH_BYTES * 2,
    )
    authkey_old = serializers.CharField(style={"input_type": "password"})
    private_key = serializers.CharField(
        min_length=settings.USER_PRIVATE_KEY_LENGTH_BYTES * 2,
        max_length=settings.USER_PRIVATE_KEY_LENGTH_BYTES * 2,
    )
    private_key_nonce = serializers.CharField(max_length=64)
    secret_key = serializers.CharField(
        min_length=settings.USER_SECRET_KEY_LENGTH_BYTES * 2,
        max_length=settings.USER_SECRET_KEY_LENGTH_BYTES * 2,
    )
    secret_key_nonce = serializers.CharField(max_length=64)
    hashing_algorithm = serializers.ChoiceField(choices=HASHING_ALGORITHMS)
    hashing_parameters = serializers.DictField()

    def validate_private_key(self, value):
        value = value.strip()
        if not re.match("^[0-9a-f]*$", value, re.IGNORECASE):
            raise exceptions.ValidationError("NO_VALID_HEX")
        return value

    def validate_private_key_nonce(self, value):
        return self.validate_private_key(value)

    def validate_secret_key(self, value):
        return self.validate_private_key(value)

    def validate_secret_key_nonce(self, value):
        return self.validate_private_key(value)

    def validate(self, attrs):
        user = self.context["request"].user
        if (
            not user.is_active
            or not user.authkey
            or not check_password(attrs["authkey_old"], user.authkey)
        ):
            raise exceptions.ValidationError("OLD_PASSWORD_INCORRECT")

        parameters = attrs["hashing_parameters"]
        if (
            "u" not in parameters
            or type(parameters["u"]) is not int
            or parameters["u"] < 14
        ):
            raise exceptions.ValidationError("INVALID_HASHING_PARAMETER")
        if (
            "r" not in parameters
            or type(parameters["r"]) is not int
            or parameters["r"] < 8
        ):
            raise exceptions.ValidationError("INVALID_HASHING_PARAMETER")
        if (
            "p" not in parameters
            or type(parameters["p"]) is not int
            or parameters["p"] < 1
        ):
            raise exceptions.ValidationError("INVALID_HASHING_PARAMETER")
        if (
            "l" not in parameters
            or type(parameters["l"]) is not int
            or parameters["l"] < 64
        ):
            raise exceptions.ValidationError("INVALID_HASHING_PARAMETER")

        if not is_weaker_hashing_profile(
            user.hashing_algorithm,
            user.hashing_parameters,
            attrs["hashing_algorithm"],
            parameters,
        ) or parameters["l"] != user.hashing_parameters.get("l"):
            raise exceptions.ValidationError("INVALID_HASHING_UPGRADE")

        return attrs
