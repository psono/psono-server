from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions
from decimal import Decimal
import re
import bcrypt

from ..models import User
from ..utils import encrypt_with_db_secret

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

        if len(settings.REGISTRATION_EMAIL_FILTER) > 0:
            email_prefix, domain = value.split("@")
            if domain not in settings.REGISTRATION_EMAIL_FILTER:
                msg = _('E-Mail not allowed to register.')
                raise exceptions.ValidationError(msg)

        # generate bcrypt with static salt.
        # I know its bad to use static salts, but its the best solution I could come up with,
        # if you want to store emails encrypted while not having to decrypt all emails for duplicate email hunt
        # Im aware that this allows attackers with this fix salt to "mass" attack all passwords.
        # if you have a better solution, please let me know.
        email_bcrypt_full = bcrypt.hashpw(value.encode(), settings.EMAIL_SECRET_SALT.encode())
        email_bcrypt = email_bcrypt_full.decode().replace(settings.EMAIL_SECRET_SALT, '', 1)

        if User.objects.filter(email_bcrypt=email_bcrypt).exists():
            msg = _('E-Mail already exists.')
            raise exceptions.ValidationError(msg)

        return value

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

        email_bcrypt_full = bcrypt.hashpw(validated_data['email'].encode(), settings.EMAIL_SECRET_SALT.encode())
        validated_data['email_bcrypt'] = email_bcrypt_full.decode().replace(settings.EMAIL_SECRET_SALT, '', 1)

        # normally encrypt emails, so they are not stored in plaintext with a random nonce
        validated_data['email'] = encrypt_with_db_secret(validated_data['email'])
        validated_data['credit'] = settings.SHARD_CREDIT_DEFAULT_NEW_USER

        return User.objects.create(**validated_data)
