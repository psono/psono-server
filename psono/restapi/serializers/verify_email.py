from ..utils import validate_activation_code

from rest_framework import serializers, exceptions


class VerifyEmailSerializeras(serializers.Serializer):
    activation_code = serializers.CharField(style={'input_type': 'password'}, required=True, )

    def validate(self, attrs: dict) -> dict:
        activation_code = attrs.get('activation_code', '').strip()

        user = validate_activation_code(activation_code)

        if not user:
            msg = 'ACTIVATION_CODE_INCORRECT'
            raise exceptions.ValidationError(msg)
        attrs['user'] = user
        attrs['activation_code'] = activation_code
        return attrs