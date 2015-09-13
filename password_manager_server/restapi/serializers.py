from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.conf import settings
from utils import validate_activation_code, authenticate
import uuid

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.contrib.auth.tokens import default_token_generator
from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from models import Token, Data_Store_Owner, Data_Store


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    authkey = serializers.CharField(style={'input_type': 'password'},  required=True)

    def validate(self, attrs):
        email = attrs.get('email')
        authkey = attrs.get('authkey')

        if email and authkey:
            owner = authenticate(email=email, authkey=authkey)
        else:
            msg = _('Must include "email" and "authkey".')
            raise exceptions.ValidationError(msg)

        if not owner:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        if not owner.is_active:
            msg = _('User account is disabled.')
            raise exceptions.ValidationError(msg)

        if not owner.is_email_active:
            msg = _('E-mail is not yet verified.')
            raise exceptions.ValidationError(msg)

        attrs['owner'] = owner
        return attrs

class VerifyEmailSerializeras(serializers.Serializer):
    activation_code = serializers.CharField(style={'input_type': 'password'}, required=True, )

    def validate(self, attrs):
        activation_code = attrs.get('activation_code').strip()

        if activation_code:
            owner = validate_activation_code(activation_code)
        else:
            msg = _('Must include "activation_code".')
            raise exceptions.ValidationError(msg)

        if not owner:
            msg = _('Activation code incorrect or already activated.')
            raise exceptions.ValidationError(msg)
        attrs['owner'] = owner
        attrs['activation_code'] = activation_code
        return attrs


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    authkey = serializers.CharField(style={'input_type': 'password'}, required=True, )

    public_key = serializers.CharField(required=True, )
    private_key = serializers.CharField(required=True, )
    private_key_nonce = serializers.CharField(required=True, )
    secret_key = serializers.CharField(required=True, )
    secret_key_nonce = serializers.CharField(required=True, )

    def validate_email(self, value):

        value = value.lower().strip()

        if Data_Store_Owner.objects.filter(email=value).exists():
            msg = _('E-Mail already exists.')
            raise exceptions.ValidationError(msg)

        return value

    def validate_authkey(self, value):

        value = value.strip()

        if len(value) < settings.AUTH_KEY_LENGTH_BYTES*2:
            msg = _('Your Auth Key is too short. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.AUTH_KEY_LENGTH_BYTES), str(settings.AUTH_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        if len(value) > settings.AUTH_KEY_LENGTH_BYTES*2:
            msg = _('Your Auth Key is too long. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.AUTH_KEY_LENGTH_BYTES), str(settings.AUTH_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        return make_password(value)

    def create(self, validated_data):
        return Data_Store_Owner.objects.create(**validated_data)


class UserDetailsSerializer(serializers.ModelSerializer):

    """
    User model w/o password
    """
    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'first_name', 'last_name')
        read_only_fields = ('email', )


class AuthkeyChangeSerializer(serializers.Serializer):

    old_authkey = serializers.CharField(style={'input_type': 'password'}, required=True, )
    new_authkey = serializers.CharField(style={'input_type': 'password'}, required=True, )

    def validate_old_authkey(self, value):
        # TODO Check for existing authkey
        return value

    def validate_new_authkey(self, value):
        if len(value) < settings.AUTH_KEY_LENGTH_BYTES*2:
            msg = _('Your Auth Key is too short. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.AUTH_KEY_LENGTH_BYTES), str(settings.AUTH_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        if len(value) > settings.AUTH_KEY_LENGTH_BYTES*2:
            msg = _('Your Auth Key is too long. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.AUTH_KEY_LENGTH_BYTES), str(settings.AUTH_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)
        return value

    def update(self, instance, validated_data):
        #TODO Check if this is working
        instance.email = validated_data.get('authkey', instance.new_authkey)
        instance.save()


class DatastoreSerializer(serializers.Serializer):

    data = serializers.CharField()
    data_nonce = serializers.CharField(max_length=64)
    type = serializers.CharField(max_length=64, default='password')
    description = serializers.CharField(max_length=64, default='default')
    secret_key = serializers.CharField(max_length=256)
    secret_key_nonce = serializers.CharField(max_length=64)


class ShareSerializer(serializers.Serializer):

    data = serializers.CharField()
    data_nonce = serializers.CharField(max_length=64)
    type = serializers.CharField(max_length=64, default='password')
    description = serializers.CharField(max_length=64, default='default')


class DatastoreOverviewSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    type = serializers.CharField(max_length=64, default='password')
    description = serializers.CharField(max_length=64, default='default')

    def validate(self, attrs):
        return attrs
