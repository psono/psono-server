from django.conf import settings
from rest_framework import serializers, exceptions
import re
import bcrypt

from ..models import User, HASHING_ALGORITHMS
from ..utils import encrypt_with_db_secret

class RegisterSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True, error_messages={ 'invalid': 'INVALID_USERNAME_FORMAT' })
    email = serializers.EmailField(required=True, error_messages={ 'invalid': 'INVALID_EMAIL_FORMAT' })
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
    hashing_algorithm = serializers.ChoiceField(choices=HASHING_ALGORITHMS, required=False, )
    hashing_parameters = serializers.DictField(required=False, )

    def validate_username(self, value):

        # According to RFC2142 all "authoritative" email addresses are:
        # ( https://www.ietf.org/rfc/rfc2142.txt )

        forbidden_usernames = [
            # SUPPORT MAILBOX NAMES FOR SPECIFIC INTERNET SERVICES
            'postmaster', 'hostmaster', 'usenet', 'news', 'webmaster', 'www', 'uucp', 'ftp',
            # BUSINESS-RELATED MAILBOX NAMES
            'info', 'marketing', 'support', 'sales',
            # BUSINESS-RELATED MAILBOX NAMES
            'security', 'abuse', 'noc',
            # OTHER NOT RFC2142 MAILBOX NAMES
            'admin', 'administrator', 'contact',
            # maybe we want later subdomains
            'smtp', 'www', 'mail', 'remote',  'blog', 'webmail', 'ns1', 'ns2', 'ns3', 'ftp', 'cdn', 'api', 'secure',
            'dev', 'web', 'cloud', 'stage', 'staging', 'repository', 'autodiscover', 'irc',
        ]

        value = value.lower().strip()

        username, domain = value.split('@', 1)

        if domain not in settings.ALLOWED_DOMAINS and '*' not in settings.ALLOWED_DOMAINS:
            msg = 'PROVIDED_DOMAIN_NOT_ALLOWED_FOR_REGISTRATION'
            raise exceptions.ValidationError(msg)

        if not re.match('^[a-z0-9.\-]*$', username, re.IGNORECASE):
            msg = 'USERNAME_VALIDATION_NAME_CONTAINS_INVALID_CHARS'
            raise exceptions.ValidationError(msg)

        if len(username) < 2:
            msg = 'Usernames may not be shorter than 2 chars.'
            raise exceptions.ValidationError(msg)

        if username.startswith('-'):
            msg = 'Usernames may not start with a dash.'
            raise exceptions.ValidationError(msg)

        if username.endswith('-'):
            msg = 'Usernames may not end with a dash.'
            raise exceptions.ValidationError(msg)

        if '--' in username:
            msg = 'Usernames may not contain consecutive dashes.'
            raise exceptions.ValidationError(msg)

        if '.-' in username:
            msg = 'Usernames may not contain periods followed by dashes.'
            raise exceptions.ValidationError(msg)

        if '-.' in username:
            msg = 'Usernames may not contain dashes followed by periods.'
            raise exceptions.ValidationError(msg)

        if username in forbidden_usernames:
            msg = 'Usernames like admin@ info@ webmaster@ and so on are forbidden.'
            raise exceptions.ValidationError(msg)

        if User.objects.filter(username=value).exists():
            msg = 'USERNAME_ALREADY_EXISTS'
            raise exceptions.ValidationError(msg)

        return value

    def validate(self, attrs: dict) -> dict:

        email = attrs.get('email')
        hashing_algorithm = attrs.get('hashing_algorithm', 'scrypt')
        hashing_parameters = attrs.get('hashing_parameters', {})

        email = email.lower().strip()

        if len(settings.REGISTRATION_EMAIL_FILTER) > 0:
            email_prefix, domain = email.split("@")
            if domain not in settings.REGISTRATION_EMAIL_FILTER:
                msg = 'EMAIL_DOMAIN_NOT_ALLOWED_TO_REGISTER'
                raise exceptions.ValidationError(msg)

        # generate bcrypt with static salt.
        # I know its bad to use static salts, but its the best solution I could come up with,
        # if you want to store emails encrypted while not having to decrypt all emails for duplicate email hunt
        # Im aware that this allows attackers with this fix salt to "mass" attack all emails.
        # if you have a better solution, please let me know.
        email_bcrypt_full = bcrypt.hashpw(email.encode(), settings.EMAIL_SECRET_SALT.encode())
        email_bcrypt = email_bcrypt_full.decode().replace(settings.EMAIL_SECRET_SALT, '', 1)

        if User.objects.filter(email_bcrypt=email_bcrypt).exists():
            msg = "USER_WITH_EMAIL_ALREADY_EXISTS"
            raise exceptions.ValidationError(msg)


        # We hardcode the settings for scrypt and the hashing parameters, as every client that is not providing them
        # is using those parameters below internally
        if not hashing_parameters:
            hashing_parameters = {
                "u": 14,
                "r": 8,
                "p": 1,
                "l": 64
            }

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

        email_bcrypt_full = bcrypt.hashpw(email.encode(), settings.EMAIL_SECRET_SALT.encode())

        attrs['hashing_algorithm'] = hashing_algorithm
        attrs['hashing_parameters'] = hashing_parameters
        attrs['email_bcrypt'] = email_bcrypt_full.decode().replace(settings.EMAIL_SECRET_SALT, '', 1)
        # normally encrypt emails, so they are not stored in plaintext with a random nonce
        attrs['email'] = encrypt_with_db_secret(email)
        attrs['credit'] = settings.SHARD_CREDIT_DEFAULT_NEW_USER

        return attrs
