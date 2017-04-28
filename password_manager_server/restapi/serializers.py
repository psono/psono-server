from django.contrib.auth.hashers import make_password
from django.conf import settings
from utils import validate_activation_code, authenticate, user_has_rights_on_share, yubikey_authenticate, yubikey_get_yubikey_id
from authentication import TokenAuthentication
import uuid
import re
import bcrypt
import hashlib
from yubico_client import Yubico

try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder

from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from models import User, Token, Google_Authenticator, Yubikey_OTP
import nacl.utils
from nacl.exceptions import CryptoError
import nacl.secret
import nacl.encoding
import pyotp


class LoginSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'Enter a valid username' })
    authkey = serializers.CharField(style={'input_type': 'password'},  required=True)
    public_key = serializers.CharField(required=True, min_length=64, max_length=64)

    def validate(self, attrs):
        username = attrs.get('username').lower().strip()
        authkey = attrs.get('authkey')
        public_key = attrs.get('public_key')

        user = authenticate(username=username, authkey=authkey)

        if not user:
            msg = _('Username or password wrong.')
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

class GAVerifySerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    ga_token = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate(self, attrs):

        ga_token = attrs.get('ga_token').lower().strip()

        if not ga_token.isdigit():
            msg = _('GA Tokens only contain digits.')
            raise exceptions.ValidationError(msg)

        token_hash = TokenAuthentication.user_token_to_token_hash(attrs.get('token'))

        try:
            token = Token.objects.filter(key=token_hash, active=False).get()
        except Token.DoesNotExist:
            msg = _('Token incorrect.')
            raise exceptions.ValidationError(msg)

        # prepare decryption
        secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)

        ga_token_correct = False
        for ga in Google_Authenticator.objects.filter(user=token.user):
            encrypted_ga_secret = nacl.encoding.HexEncoder.decode(ga.secret)
            decrypted_ga_secret = crypto_box.decrypt(encrypted_ga_secret)
            totp = pyotp.TOTP(decrypted_ga_secret)
            if totp.verify(ga_token):
                ga_token_correct = True
                break

        if not ga_token_correct:
            msg = _('GA Token incorrect.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs

class YubikeyOTPVerifySerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    yubikey_otp = serializers.CharField(required=True)

    def validate(self, attrs):

        yubikey_otp = attrs.get('yubikey_otp').strip()

        yubikey_is_valid = yubikey_authenticate(yubikey_otp)

        if yubikey_is_valid is None:
            msg = _('Server does not support YubiKeys.')
            raise exceptions.ValidationError(msg)

        if not yubikey_is_valid:
            msg = _('YubiKey OTP incorrect.')
            raise exceptions.ValidationError(msg)

        token_hash = TokenAuthentication.user_token_to_token_hash(attrs.get('token'))

        try:
            token = Token.objects.filter(key=token_hash, active=False).get()
        except Token.DoesNotExist:
            msg = _('Token incorrect.')
            raise exceptions.ValidationError(msg)

        # prepare decryption
        secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)

        yubikey_id = yubikey_get_yubikey_id(yubikey_otp)

        otp_token_correct = False
        for yk in Yubikey_OTP.objects.filter(user=token.user):
            encrypted_yubikey_id = nacl.encoding.HexEncoder.decode(yk.yubikey_id)
            decrypted_yubikey_id = crypto_box.decrypt(encrypted_yubikey_id)

            if yubikey_id == decrypted_yubikey_id:
                otp_token_correct = True
                break

        if not otp_token_correct:
            msg = _('YubiKey OTP incorrect.')
            raise exceptions.ValidationError(msg)

        attrs['token'] = token
        return attrs

class ActivateTokenSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    verification = serializers.CharField(required=True)
    verification_nonce = serializers.CharField(max_length=64, required=True)

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

        if token.google_authenticator_2fa:
            msg = _('GA challenge unsolved.')
            raise exceptions.ValidationError(msg)

        if token.google_authenticator_2fa:
            msg = _('YubiKey challenge unsolved.')
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

class LogoutSerializer(serializers.Serializer):
    token = serializers.CharField(required=False)

    def validate(self, attrs):

        token = attrs.get('token', False)
        if token:
            attrs['token_hash'] = TokenAuthentication.user_token_to_token_hash(token)
        else:
            attrs['token_hash'] = TokenAuthentication.get_token_hash(self.context['request'])

        return attrs


class VerifyEmailSerializeras(serializers.Serializer):
    activation_code = serializers.CharField(style={'input_type': 'password'}, required=True, )

    def validate(self, attrs):
        activation_code = attrs.get('activation_code').strip()

        user = validate_activation_code(activation_code)

        if not user:
            msg = _('Activation code incorrect or already activated.')
            raise exceptions.ValidationError(msg)
        attrs['user'] = user
        attrs['activation_code'] = activation_code
        return attrs


class RegisterSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'Enter a valid username' })
    email = serializers.EmailField(required=True)
    authkey = serializers.CharField(style={'input_type': 'password'}, required=True,
                                    min_length=settings.AUTH_KEY_LENGTH_BYTES*2,
                                    max_length=settings.AUTH_KEY_LENGTH_BYTES*2)

    public_key = serializers.CharField(required=True,
                                       min_length=settings.USER_PUBLIC_KEY_LENGTH_BYTES*2,
                                       max_length=settings.USER_PUBLIC_KEY_LENGTH_BYTES*2)
    private_key = serializers.CharField(required=True,
                                        min_length=settings.USER_PRIVATE_KEY_LENGTH_BYTES*2,
                                        max_length=settings.USER_PRIVATE_KEY_LENGTH_BYTES*2)
    private_key_nonce = serializers.CharField(max_length=64, required=True, )
    secret_key = serializers.CharField(required=True,
                                       min_length=settings.USER_SECRET_KEY_LENGTH_BYTES*2,
                                       max_length=settings.USER_SECRET_KEY_LENGTH_BYTES*2)
    secret_key_nonce = serializers.CharField(max_length=64, required=True, )
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

        if username.startswith('-'):
            msg = _('Usernames may not start with a dash.')
            raise exceptions.ValidationError(msg)

        if username.endswith('-'):
            msg = _('Usernames may not end with a dash.')
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
        return make_password(value.strip())

    def create(self, validated_data):

        validated_data['email_bcrypt'] = bcrypt.hashpw(validated_data['email'].encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)

        # normally encrypt emails, so they are not stored in plaintext with a random nonce
        secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
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
    email = serializers.EmailField(required=False, allow_null=True)
    authkey = serializers.CharField(style={'input_type': 'password'}, required=False, allow_null=True,
                                    max_length=settings.AUTH_KEY_LENGTH_BYTES*2,
                                    min_length=settings.AUTH_KEY_LENGTH_BYTES*2)
    authkey_old = serializers.CharField(style={'input_type': 'password'}, required=True,
                                    max_length=settings.AUTH_KEY_LENGTH_BYTES*2,
                                    min_length=settings.AUTH_KEY_LENGTH_BYTES*2)

    private_key = serializers.CharField(required=False, allow_null=True,
                                    max_length=settings.USER_PRIVATE_KEY_LENGTH_BYTES*2,
                                    min_length=settings.USER_PRIVATE_KEY_LENGTH_BYTES*2)
    private_key_nonce = serializers.CharField(max_length=64, required=False, allow_null=True)
    secret_key = serializers.CharField(required=False, allow_null=True,
                                    max_length=settings.USER_SECRET_KEY_LENGTH_BYTES*2,
                                    min_length=settings.USER_SECRET_KEY_LENGTH_BYTES*2)
    secret_key_nonce = serializers.CharField(max_length=64, required=False, allow_null=True)

    def validate(self, attrs):
        email = attrs.get('email')

        if email:
            email = email.lower().strip()
            email_bcrypt = bcrypt.hashpw(email.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(
                settings.EMAIL_SECRET_SALT, '', 1)
            if User.objects.filter(email_bcrypt=email_bcrypt).exclude(pk=self.context['request'].user.pk).exists():
                msg = _('E-Mail already exists.')
                raise exceptions.ValidationError(msg)
            attrs['email'] = email

        return attrs

    def validate_private_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('private_key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('secret_key_nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_secret_key(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('secret_key must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_private_key_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('private_key_nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value


class NewGASerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)

class NewYubikeyOTPSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=256)
    yubikey_otp = serializers.CharField(max_length=64)


    def validate_yubikey_otp(self, value):

        value = value.strip()

        if settings.YUBIKEY_CLIENT_ID is None or settings.YUBIKEY_SECRET_KEY is None:
            msg = _('Server does not support Yubikeys')
            raise exceptions.ValidationError(msg)

        client = Yubico(settings.YUBIKEY_CLIENT_ID, settings.YUBIKEY_SECRET_KEY)
        try:
            yubikey_is_valid = client.verify(value)
        except:
            yubikey_is_valid = False

        if not yubikey_is_valid:
            msg = _('Yubikey token invalid')
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


class CreateRecoverycodeSerializer(serializers.Serializer):

    recovery_authkey = serializers.CharField(required=True)
    recovery_data = serializers.CharField(required=True)
    recovery_data_nonce = serializers.CharField(max_length=64, required=True)
    recovery_sauce = serializers.CharField(max_length=64, required=True)


    def validate_recovery_data(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Recovery data must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_recovery_data_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Recovery data nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value


class EnableNewPasswordSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'Enter a valid username' })
    recovery_authkey = serializers.CharField(required=True)


class SetNewPasswordSerializer(serializers.Serializer):

    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'Enter a valid username' })
    recovery_authkey = serializers.CharField(required=True)
    update_data = serializers.CharField(required=True)
    update_data_nonce = serializers.CharField(max_length=64, required=True)



    def validate_update_data(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Update data must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value


    def validate_update_data_nonce(self, value):

        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('Update data nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

class ShareTreeSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    parent_share = PublicShareDetailsSerializer()
    child_share = PublicShareDetailsSerializer()


class CreateShareSerializer(serializers.Serializer):

    id = serializers.UUIDField(default=uuid.uuid4)
    data = serializers.CharField(required=True)
    data_nonce = serializers.CharField(required=True, max_length=64)
    key = serializers.CharField(max_length=256)
    key_nonce = serializers.CharField(max_length=64)

    def validate_data(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('data must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

    def validate_data_nonce(self, value):
        value = value.strip()

        if not re.match('^[0-9a-f]*$', value, re.IGNORECASE):
            msg = _('data_nonce must be in hex representation')
            raise exceptions.ValidationError(msg)

        return value

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

