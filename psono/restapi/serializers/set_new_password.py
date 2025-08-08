from django.conf import settings
from django.utils import timezone
from django.contrib.auth.hashers import check_password

from rest_framework import serializers, exceptions

from ..models import User, Recovery_Code, HASHING_ALGORITHMS

import re

import nacl, datetime
import nacl.encoding


class SetNewPasswordSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'INVALID_USERNAME_FORMAT' })
    recovery_authkey = serializers.CharField(required=True)
    update_data = serializers.CharField(required=True)
    update_data_nonce = serializers.CharField(max_length=64, required=True)
    hashing_algorithm = serializers.ChoiceField(choices=HASHING_ALGORITHMS, required=False, )
    hashing_parameters = serializers.DictField(required=False, )


    def validate_update_data(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = 'NO_VALID_HEX'
            raise exceptions.ValidationError(msg)

        return value


    def validate_update_data_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = 'NO_VALID_HEX'
            raise exceptions.ValidationError(msg)

        return value

    def validate(self, attrs: dict) -> dict:

        username = attrs.get('username')
        recovery_authkey = attrs.get('recovery_authkey')
        hashing_algorithm = attrs.get('hashing_algorithm', '')
        hashing_parameters = attrs.get('hashing_parameters', {})

        update_data = nacl.encoding.HexEncoder.decode(attrs.get('update_data'))
        update_data_nonce = nacl.encoding.HexEncoder.decode(attrs.get('update_data_nonce'))

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            msg = "USERNAME_OR_RECOVERY_CODE_INCORRECT"
            raise exceptions.ValidationError(msg)

        try:
            recovery_code = Recovery_Code.objects.get(user_id=user.id)

            if not check_password(recovery_authkey, recovery_code.recovery_authkey):
                msg = "USERNAME_OR_RECOVERY_CODE_INCORRECT"
                raise exceptions.ValidationError(msg)

        except Recovery_Code.DoesNotExist:
            msg = "USERNAME_OR_RECOVERY_CODE_INCORRECT"
            raise exceptions.ValidationError(msg)


        if recovery_code.verifier_issue_date + datetime.timedelta(0,settings.RECOVERY_VERIFIER_TIME_VALID) < timezone.now():
            msg = "VALIDATOR_EXPIRED"
            raise exceptions.ValidationError(msg)

        # Either both are provided or none
        if hashing_algorithm and not hashing_parameters:
            msg = 'INVALID_HASHING_PARAMETER'
            raise exceptions.ValidationError(msg)

        if not hashing_algorithm and hashing_parameters:
            msg = 'INVALID_HASHING_PARAMETER'
            raise exceptions.ValidationError(msg)

        if hashing_algorithm == 'scrypt':
            if 'u' not in hashing_parameters or hashing_parameters['u'] < 14:
                msg = 'INVALID_HASHING_PARAMETER'
                raise exceptions.ValidationError(msg)
            if 'r' not in hashing_parameters or hashing_parameters['r'] < 8:
                msg = 'INVALID_HASHING_PARAMETER'
                raise exceptions.ValidationError(msg)
            if 'p' not in hashing_parameters or hashing_parameters['p'] < 1:
                msg = 'INVALID_HASHING_PARAMETER'
                raise exceptions.ValidationError(msg)
            if 'l' not in hashing_parameters or hashing_parameters['l'] < 64:
                msg = 'INVALID_HASHING_PARAMETER'
                raise exceptions.ValidationError(msg)

        attrs['hashing_algorithm'] = hashing_algorithm or user.hashing_algorithm
        attrs['hashing_parameters'] = hashing_parameters or user.hashing_parameters
        attrs['update_data'] = update_data
        attrs['update_data_nonce'] = update_data_nonce
        attrs['recovery_code'] = recovery_code
        attrs['user'] = user

        return attrs