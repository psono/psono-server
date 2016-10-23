from django.contrib.auth.hashers import make_password
from django.conf import settings
from utils import validate_activation_code, authenticate, user_has_rights_on_share, is_uuid
from authentication import TokenAuthentication
import uuid
import re
import bcrypt
import hashlib

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from models import User, Token
import nacl.utils
from nacl.exceptions import CryptoError
import nacl.secret
import nacl.encoding


class LoginSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True)
    authkey = serializers.CharField(style={'input_type': 'password'},  required=True)
    public_key = serializers.CharField(required=True)

    def validate(self, attrs):
        username = attrs.get('username').lower().strip()
        authkey = attrs.get('authkey')
        public_key = attrs.get('public_key')

        if username and authkey:
            user = authenticate(username=username, authkey=authkey)
        else:
            msg = _('Must include "username" and "authkey".')
            raise exceptions.ValidationError(msg)

        if not user:
            msg = _('Username or password wrong.')
            raise exceptions.ValidationError(msg)

        if len(public_key) != 64:
            msg = _('Session public key seems invalid.')
            raise exceptions.ValidationError(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.ValidationError(msg)

        if not user.is_email_active:
            msg = _('E-mail is not yet verified.')
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        attrs['user_session_public_key'] = public_key
        return attrs

class ActivateTokenSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    verification = serializers.CharField(required=True)
    verification_nonce = serializers.CharField(required=True)

    def validate(self, attrs):
        verification_hex = attrs.get('verification')
        verification = nacl.encoding.HexEncoder.decode(verification_hex)
        verification_nonce_hex = attrs.get('verification_nonce')
        verification_nonce = nacl.encoding.HexEncoder.decode(verification_nonce_hex)

        token_hash = TokenAuthentication.user_token_to_token_hash(attrs.get('token'))

        try:
            token = Token.objects.filter(key=token_hash, active=False).get()
        except Token.DoesNotExist:
            msg = _('Token incorrect.')
            raise exceptions.ValidationError(msg)

        crypto_box = nacl.secret.SecretBox(token.secret_key, encoder=nacl.encoding.HexEncoder)

        try:
            decrypted = crypto_box.decrypt(verification, verification_nonce)
        except CryptoError:
            msg = _('Verification code incorrect.')
            raise exceptions.ValidationError(msg)


        if token.user_validator != decrypted:
            msg = _('Verification code incorrect.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs


class VerifyEmailSerializeras(serializers.Serializer):
    activation_code = serializers.CharField(style={'input_type': 'password'}, required=True, )

    def validate(self, attrs):
        activation_code = attrs.get('activation_code').strip()

        if activation_code:
            user = validate_activation_code(activation_code)
        else:
            msg = _('Must include "activation_code".')
            raise exceptions.ValidationError(msg)

        if not user:
            msg = _('Activation code incorrect or already activated.')
            raise exceptions.ValidationError(msg)
        attrs['user'] = user
        attrs['activation_code'] = activation_code
        return attrs


class RegisterSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True)
    email = serializers.EmailField(required=True)
    authkey = serializers.CharField(style={'input_type': 'password'}, required=True, )

    public_key = serializers.CharField(required=True, )
    private_key = serializers.CharField(required=True, )
    private_key_nonce = serializers.CharField(required=True, )
    secret_key = serializers.CharField(required=True, )
    secret_key_nonce = serializers.CharField(required=True, )
    user_sauce = serializers.CharField(required=True, )

    def validate_email(self, value):

        value = value.lower().strip()

        # generate bcrypt with static salt.
        # I know its bad to use static salts, but its the best solution I could come up with,
        # if you want to store emails encrypted while not having to decrypt all emails for duplicate email hunt
        # Im aware that this allows attackers with this fix salt to "mass" attack all passwords.
        # if you have a better solution, please let me know.
        email_bcrypt = bcrypt.hashpw(value.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)

        if User.objects.filter(email_bcrypt=email_bcrypt).exists():
            msg = _('E-Mail already exists.')
            raise exceptions.ValidationError(msg)

        return value

    def validate_username(self, value):

        # According to RFC2142 all "authoritative" email addresses are:
        # ( https://www.ietf.org/rfc/rfc2142.txt )

        forbidden_usernames = [
            # SUPPORT MAILBOX NAMES FOR SPECIFIC INTERNET SERVICES
            'postmaster',
            'hostmaster',
            'usenet',
            'news',
            'webmaster',
            'www',
            'uucp',
            'ftp',
            # BUSINESS-RELATED MAILBOX NAMES
            'info',
            'marketing',
            'support',
            'sales',
            # BUSINESS-RELATED MAILBOX NAMES
            'security',
            'abuse',
            'noc',
            # OTHER NOT RFC2142 MAILBOX NAMES
            'admin',
            'administrator',
            'contact',
        ]

        value = value.lower().strip()

        username, domain = value.split('@', 1)

        if domain not in settings.ALLOWED_DOMAINS:
            msg = _('The provided domain in your username is not allowed for the registration on this server.')
            raise exceptions.ValidationError(msg)

        if not re.match('^[a-z0-9.\-]*$', username, re.IGNORECASE):
            msg = _('Usernames may only contain letters, numbers, periods and dashes.')
            raise exceptions.ValidationError(msg)

        if len(username) < 3:
            msg = _('Usernames may not be shorter than 3 chars.')
            raise exceptions.ValidationError(msg)

        if username.startswith('.'):
            msg = _('Usernames may not start with a period.')
            raise exceptions.ValidationError(msg)

        if username.startswith('-'):
            msg = _('Usernames may not start with a dash.')
            raise exceptions.ValidationError(msg)

        if username.endswith('.'):
            msg = _('Usernames may not end with a period.')
            raise exceptions.ValidationError(msg)

        if username.endswith('-'):
            msg = _('Usernames may not end with a dash.')
            raise exceptions.ValidationError(msg)

        if '..' in username:
            msg = _('Usernames may not contain consecutive periods.')
            raise exceptions.ValidationError(msg)

        if '--' in username:
            msg = _('Usernames may not contain consecutive dashes.')
            raise exceptions.ValidationError(msg)

        if '.-' in username:
            msg = _('Usernames may not contain periods followed by dashes.')
            raise exceptions.ValidationError(msg)

        if '-.' in username:
            msg = _('Usernames may not contain dashes followed by periods.')
            raise exceptions.ValidationError(msg)

        if username in forbidden_usernames:
            msg = _('Usernames like admin@ info@ webmaster@ and so on are forbidden.')
            raise exceptions.ValidationError(msg)

        if User.objects.filter(username=value).exists():
            msg = _('Username already exists.')
            raise exceptions.ValidationError(msg)

        return value

    def validate_authkey(self, value):

        value = value.strip()

        if len(value) < settings.AUTH_KEY_LENGTH_BYTES*2:
            msg = _('Your auth key is too short. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.AUTH_KEY_LENGTH_BYTES), str(settings.AUTH_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        if len(value) > settings.AUTH_KEY_LENGTH_BYTES*2:
            msg = _('Your auth key is too long. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.AUTH_KEY_LENGTH_BYTES), str(settings.AUTH_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        return make_password(value)

    def validate_public_key(self, value):

        value = value.strip()

        if len(value) < settings.USER_PUBLIC_KEY_LENGTH_BYTES*2:
            msg = _('Your public key is too short. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_PUBLIC_KEY_LENGTH_BYTES), str(settings.USER_PUBLIC_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        if len(value) > settings.USER_PUBLIC_KEY_LENGTH_BYTES*2:
            msg = _('Your public key is too long. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_PUBLIC_KEY_LENGTH_BYTES), str(settings.USER_PUBLIC_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key(self, value):

        value = value.strip()

        if len(value) < settings.USER_PRIVATE_KEY_LENGTH_BYTES*2:
            msg = _('Your private key is too short. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_PRIVATE_KEY_LENGTH_BYTES), str(settings.USER_PRIVATE_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        if len(value) > settings.USER_PRIVATE_KEY_LENGTH_BYTES*2:
            msg = _('Your private key is too long. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_PRIVATE_KEY_LENGTH_BYTES), str(settings.USER_PRIVATE_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key(self, value):

        value = value.strip()

        if len(value) < settings.USER_SECRET_KEY_LENGTH_BYTES*2:
            msg = _('Your secret key is too short. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_SECRET_KEY_LENGTH_BYTES), str(settings.USER_SECRET_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        if len(value) > settings.USER_SECRET_KEY_LENGTH_BYTES*2:
            msg = _('Your secret key is too long. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_SECRET_KEY_LENGTH_BYTES), str(settings.USER_SECRET_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        return value

    def validate_user_sauce(self, value):

        value = value.strip()

        if len(value) < 1:
            msg = _('You forgot to specify a user sauce') % \
                  (str(settings.USER_SECRET_KEY_LENGTH_BYTES), str(settings.USER_SECRET_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        return value

    def create(self, validated_data):

        validated_data['email_bcrypt'] = bcrypt.hashpw(validated_data['email'].encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)

        # normally encrypt emails, so they are not stored in plaintext with a random nonce
        secret_key = hashlib.sha256(settings.EMAIL_SECRET).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        encrypted_email = crypto_box.encrypt(validated_data['email'].encode('utf-8'), nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
        validated_data['email'] = nacl.encoding.HexEncoder.encode(encrypted_email)

        return User.objects.create(**validated_data)


class PublicUserDetailsSerializer(serializers.Serializer):
    id = serializers.UUIDField(default=uuid.uuid4)


class PublicShareDetailsSerializer(serializers.Serializer):
    id = serializers.UUIDField(default=uuid.uuid4)

class DatastoreSerializer(serializers.Serializer):

    data = serializers.CharField()
    data_nonce = serializers.CharField(max_length=64)
    type = serializers.CharField(max_length=64, default='password')
    description = serializers.CharField(max_length=64, default='default')
    secret_key = serializers.CharField(max_length=256)
    secret_key_nonce = serializers.CharField(max_length=64)



class SecretSerializer(serializers.Serializer):

    data = serializers.CharField()
    data_nonce = serializers.CharField(max_length=64)
    type = serializers.CharField(max_length=64, default='password')


class UserPublicKeySerializer(serializers.Serializer):

    user_id = serializers.UUIDField(default=uuid.uuid4)
    user_email = serializers.EmailField(required=False)


class UserUpdateSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    authkey = serializers.CharField(style={'input_type': 'password'}, required=True, )
    authkey_old = serializers.CharField(style={'input_type': 'password'}, required=True, )

    private_key = serializers.CharField(required=True, )
    private_key_nonce = serializers.CharField(required=True, )
    secret_key = serializers.CharField(required=True, )
    secret_key_nonce = serializers.CharField(required=True, )

    def validate_email(self, value):

        value = value.lower().strip()

        email_bcrypt = bcrypt.hashpw(value.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)

        if User.objects.filter(email_bcrypt=email_bcrypt).exclude(pk=self.context['request'].user.pk).exists():
            msg = _('E-Mail already exists.')
            raise exceptions.ValidationError(msg)

        return value

    def validate_authkey(self, value):

        value = value.strip()

        if len(value) < settings.AUTH_KEY_LENGTH_BYTES*2:
            msg = _('Your auth key is too short. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.AUTH_KEY_LENGTH_BYTES), str(settings.AUTH_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        if len(value) > settings.AUTH_KEY_LENGTH_BYTES*2:
            msg = _('Your auth key is too long. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.AUTH_KEY_LENGTH_BYTES), str(settings.AUTH_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        return value

    def validate_authkey_old(self, value):

        value = value.strip()

        if len(value) < settings.AUTH_KEY_LENGTH_BYTES*2 or len(value) > settings.AUTH_KEY_LENGTH_BYTES*2:
            msg = _('Your old password was not right.')
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key(self, value):

        value = value.strip()

        if len(value) < settings.USER_PRIVATE_KEY_LENGTH_BYTES*2:
            msg = _('Your private key is too short. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_PRIVATE_KEY_LENGTH_BYTES), str(settings.USER_PRIVATE_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        if len(value) > settings.USER_PRIVATE_KEY_LENGTH_BYTES*2:
            msg = _('Your private key is too long. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_PRIVATE_KEY_LENGTH_BYTES), str(settings.USER_PRIVATE_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key(self, value):

        value = value.strip()

        if len(value) < settings.USER_SECRET_KEY_LENGTH_BYTES*2:
            msg = _('Your secret key is too short. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_SECRET_KEY_LENGTH_BYTES), str(settings.USER_SECRET_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        if len(value) > settings.USER_SECRET_KEY_LENGTH_BYTES*2:
            msg = _('Your secret key is too long. It needs to have %s Bytes (%s digits in hex)') % \
                  (str(settings.USER_SECRET_KEY_LENGTH_BYTES), str(settings.USER_SECRET_KEY_LENGTH_BYTES*2), )
            raise exceptions.ValidationError(msg)

        return value


class UserShareSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    key = serializers.CharField(max_length=256)
    key_nonce = serializers.CharField(max_length=64)
    title = serializers.CharField(max_length=256)
    read = serializers.BooleanField()
    write = serializers.BooleanField()
    grant = serializers.BooleanField()

    user = PublicUserDetailsSerializer()


class CreateUserShareRightSerializer(serializers.Serializer):
    key = serializers.CharField(max_length=256, required=False)
    key_nonce = serializers.CharField(max_length=64, required=False)
    title = serializers.CharField(max_length=512, required=False)
    title_nonce = serializers.CharField(max_length=64, required=False)
    type = serializers.CharField(max_length=512, required=False)
    type_nonce = serializers.CharField(max_length=64, required=False)
    share_id = serializers.UUIDField(required=True)
    user_id = serializers.UUIDField(required=True)
    read = serializers.BooleanField()
    write = serializers.BooleanField()
    grant = serializers.BooleanField()

    def validate(self, attrs):

        # check permissions on share
        if not user_has_rights_on_share(self.context['request'].user.id, attrs['share_id'], grant=True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # check if user exists
        try:
            attrs['user'] = User.objects.get(pk=attrs['user_id'])
        except User.DoesNotExist:
            msg = _('Target user does not exist.".')
            raise exceptions.ValidationError(msg)

        return attrs


class UpdateUserShareRightSerializer(serializers.Serializer):
    share_id = serializers.UUIDField(required=True)
    user_id = serializers.UUIDField(required=True)
    read = serializers.BooleanField()
    write = serializers.BooleanField()
    grant = serializers.BooleanField()

    def validate(self, attrs):

        # check permissions on share
        if not user_has_rights_on_share(self.context['request'].user.id, attrs['share_id'], grant=True):
            msg = _("You don't have permission to access or it does not exist.")
            raise exceptions.ValidationError(msg)

        # check if user exists
        try:
            attrs['user'] = User.objects.get(pk=attrs['user_id'])
        except User.DoesNotExist:
            msg = _('Target user does not exist.".')
            raise exceptions.ValidationError(msg)

        return attrs


class ShareTreeSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    parent_share = PublicShareDetailsSerializer()
    child_share = PublicShareDetailsSerializer()

class CreateShareSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    data = serializers.CharField()
    data_nonce = serializers.CharField(max_length=64)
    key = serializers.CharField(max_length=256)
    key_nonce = serializers.CharField(max_length=64)

    def validate(self, attrs):
        data = attrs.get('data')
        data_nonce = attrs.get('data_nonce')

        if not data or not data_nonce:
            msg = _('Must include "data" and "data_nonce".')
            raise exceptions.ValidationError(msg)

        return attrs


class DatastoreOverviewSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    type = serializers.CharField(max_length=64, default='password')
    description = serializers.CharField(max_length=64, default='default')


class SecretOverviewSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)


class ShareOverviewSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    data = serializers.CharField()
    data_nonce = serializers.CharField(max_length=64)
    user = serializers.UUIDField(default=uuid.uuid4)

