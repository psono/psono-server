from ..utils import validate_unregister_code

from rest_framework import serializers, exceptions


class UpdateUnregisterSerializer(serializers.Serializer):
    unregister_code = serializers.CharField(style={'input_type': 'password'}, required=True, )

    def validate(self, attrs: dict) -> dict:
        unregister_code = attrs.get('unregister_code', '').strip()

        user = validate_unregister_code(unregister_code)

        if not user:
            msg = 'UNREGISTRATION_CODE_INCORRECT'
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        attrs['unregister_code'] = unregister_code

        return attrs
