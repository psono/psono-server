from datetime import timedelta
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import HTTP_HEADER_ENCODING, exceptions
from raven.contrib.django.raven_compat.models import client

from hashlib import sha512
import json
import binascii
import dateutil.parser
import datetime

from .parsers import decrypt
from .models import Token, User, Fileserver_Cluster_Members, Fileserver_Cluster, Fileserver_Cluster_Shard_Link, Fileserver_Cluster_Member_Shard_Link, File_Transfer
from .utils import get_cache, decrypt_with_db_secret, get_ip

import nacl.exceptions
import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box


def get_authorization_validator_header(request):
    """
    Return request's 'Authorization:' header, as a bytestring.

    Hide some test client ickyness where the header can be unicode.
    """
    auth = request.META.get('HTTP_AUTHORIZATION_VALIDATOR', b'')
    if isinstance(auth, str):
        # Work around django test client oddness
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth


class TokenAuthentication(BaseAuthentication):
    """
    Token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:

        Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a
    """

    model = Token
    allow_inactive = False
    """
    A custom token model may be used, but must have the following properties.

    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    def authenticate(self, request):
        token_hash = self.get_token_hash(request)
        token = self.get_db_token(token_hash)

        user = get_cache(User, token.user_id)

        if not user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        if not user.is_email_active:
            raise exceptions.AuthenticationFailed(_('Account not yet verified.'))

        if token.device_fingerprint or token.client_date:
            token_validator_encrypted = self.get_token_validator(request)
            try:
                token_validator_json = decrypt(token.secret_key, token_validator_encrypted['text'], token_validator_encrypted['nonce'])
            except binascii.Error:
                msg = _('Invalid token header. Not proper encrypted.')
                raise exceptions.AuthenticationFailed(msg)


            token_validator = json.loads(token_validator_json.decode())

            if not settings.DEVICE_PROTECTION_DISABLED:
                request_device_fingerprint = token_validator.get('request_device_session', token_validator.get('request_device_fingerprint', False))
                if not request_device_fingerprint:
                    token.delete()
                    raise exceptions.AuthenticationFailed('Device Fingerprint Protection: request_device_fingerprint missing')
                if not constant_time_compare(str(request_device_fingerprint), str(token.device_fingerprint)):
                    token.delete()
                    raise exceptions.AuthenticationFailed('Device Fingerprint Protection: device_fingerprint mismatch')

            if not settings.REPLAY_PROTECTION_DISABLED:
                client_date = token.client_date
                create_date = token.create_date
                request_date = token_validator.get('request_time', False)
                now = timezone.now()

                if not request_date:
                    token.delete()
                    raise exceptions.AuthenticationFailed('Replay Protection: request_time missing')

                request_date = dateutil.parser.parse(request_date)
                time_difference = abs(((client_date - create_date) - (request_date - now)).total_seconds())
                if time_difference > settings.REPLAY_PROTECTION_TIME_DFFERENCE:
                    token.delete()
                    raise exceptions.AuthenticationFailed('Replay Protection: Time difference too big')

        request.user = user
        user.session_secret_key = token.secret_key

        client.context.merge({'user': {
            'username': request.user.username
        }})

        if settings.AUTO_PROLONGATION_TOKEN_TIME_VALID and request.path.lower() not in settings.AUTO_PROLONGATION_URL_EXCEPTIONS:
            token.valid_till = timezone.now() + timedelta(seconds=settings.AUTO_PROLONGATION_TOKEN_TIME_VALID)
            token.save()

        return user, token

    @staticmethod
    def user_token_to_token_hash(token):
        return sha512(token.encode()).hexdigest()

    @staticmethod
    def get_token_hash(request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'token':
            msg = _('Invalid token header. No token header present.')
            raise exceptions.AuthenticationFailed(msg)

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)
        return TokenAuthentication.user_token_to_token_hash(token)


    @staticmethod
    def get_token_validator(request):
        auth = get_authorization_validator_header(request)
        try:
            auth = auth.decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        if auth == '':
            msg = _('Invalid token header. Incorrect format in token header.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            auth = json.loads(auth)
        except ValueError:
            msg = _('Invalid token header. Incorrect format in token header.')
            raise exceptions.AuthenticationFailed(msg)

        if 'text' not in auth:
            msg = _('Invalid token header. Token attribute not present.')
            raise exceptions.AuthenticationFailed(msg)

        if 'nonce' not in auth:
            msg = _('Invalid token header. Token attribute not present.')
            raise exceptions.AuthenticationFailed(msg)

        return auth

    def get_db_token(self, token_hash):

        token = get_cache(Token, token_hash)

        if token is None:
            raise exceptions.AuthenticationFailed(_('Invalid token or not yet activated.'))

        if not self.allow_inactive and not token.active:
            raise exceptions.AuthenticationFailed(_('Invalid token or not yet activated.'))

        if token.valid_till < timezone.now():
            raise exceptions.AuthenticationFailed(_('Invalid token or not yet activated.'))

        return token

    def authenticate_header(self, request):
        return 'Token'


class FileTransferAuthentication(BaseAuthentication):
    """
    File transfer based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:

        Authorization: Filetransfer 71a1878c-d5a0-49d8-ab17-eba0046e4018

    """

    model = Token
    allow_inactive = False
    """
    A custom token model may be used, but must have the following properties.

    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    def authenticate(self, request):
        file_transfer_id = self.get_file_transfer_id(request)

        try:
            file_transfer = File_Transfer.objects.select_related('user').get(pk=file_transfer_id)
        except File_Transfer.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('FILE_TRANSFER_INVALID'))

        if not file_transfer.user.is_active:
            raise exceptions.AuthenticationFailed(_('USER_INACTIVE_OR_DELETED'))

        if not file_transfer.user.is_email_active:
            raise exceptions.AuthenticationFailed(_('ACCOUNT_NOT_VERIFIED'))

        request.user = file_transfer.user
        file_transfer.session_secret_key = file_transfer.secret_key
        file_transfer.write = True

        client.context.merge({'user': {
            'username': request.user.username
        }})

        return file_transfer.user, file_transfer


    @staticmethod
    def get_file_transfer_id(request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'filetransfer':
            msg = _('Invalid filetransfer header. No token header present.')
            raise exceptions.AuthenticationFailed(msg)

        if len(auth) == 1:
            msg = _('Invalid filetransfer header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid filetransfer header. File transfer id string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            file_transfer_id = auth[1].decode()
        except UnicodeError:
            msg = _('Invalid filetransfer header. File transfer id string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        return file_transfer_id

    def authenticate_header(self, request):
        return 'Filetransfer'

class FileserverAuthentication(TokenAuthentication):

    def authenticate(self, request):
        token_hash = self.get_token_hash(request)

        try:
            fileserver = Fileserver_Cluster_Members.objects.get(key=token_hash, valid_till__gte=timezone.now())
        except Fileserver_Cluster_Members.DoesNotExist:
            msg = _('Fileserver not alive.')
            raise exceptions.AuthenticationFailed(msg)

        return fileserver, fileserver

class FileserverAliveAuthentication(TokenAuthentication):

    def authenticate(self, request):
        try:
            token_hash = self.get_token_hash(request)
        except exceptions.AuthenticationFailed:
            token_hash = None

        fileserver = None
        if token_hash is not None:
            try:
                fileserver = Fileserver_Cluster_Members.objects.only('pk').get(key=token_hash)
            except Fileserver_Cluster_Members.DoesNotExist:
                pass

        if fileserver is None and token_hash is not None:
            cluster_id, fileserver_info_enc = self.get_fileserver_validator(request)
            try:
                cluster = Fileserver_Cluster.objects.get(pk=cluster_id)
            except Fileserver_Cluster.DoesNotExist:
                msg = _('Invalid token header. Cluster ID does not exist.')
                raise exceptions.AuthenticationFailed(msg)

            cluster_public_key = decrypt_with_db_secret(cluster.auth_public_key)

            cluster_crypto_box = Box(PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
                                     PublicKey(cluster_public_key, encoder=nacl.encoding.HexEncoder))

            try:
                fileserver_info = json.loads(cluster_crypto_box.decrypt(nacl.encoding.HexEncoder.decode(fileserver_info_enc)).decode())
            except nacl.exceptions.CryptoError:
                msg = _('Invalid fileserver info.')
                raise exceptions.AuthenticationFailed(msg)

            if not constant_time_compare(fileserver_info['CLUSTER_ID'], cluster_id):
                msg = _('Invalid fileserver info.')
                raise exceptions.AuthenticationFailed(msg)

            if not constant_time_compare(FileserverAliveAuthentication.user_token_to_token_hash(fileserver_info['FILESERVER_ID']), token_hash):
                msg = _('Invalid fileserver info.')
                raise exceptions.AuthenticationFailed(msg)

            self.validate_cluster_shard_access(cluster_id, fileserver_info['SHARDS_PUBLIC'])

            fileserver = Fileserver_Cluster_Members.objects.create(
                create_ip=get_ip(request),
                fileserver_cluster_id=cluster_id,
                key=token_hash,
                public_key=fileserver_info['FILESERVER_PUBLIC_KEY'],
                secret_key=fileserver_info['FILESERVER_SESSION_KEY'],
                version=fileserver_info['VERSION'],
                hostname=fileserver_info['HOSTNAME'],
                url=fileserver_info['HOST_URL'],
                read=fileserver_info['READ'],
                write=fileserver_info['WRITE'],
                allow_link_shares=fileserver_info.get('ALLOW_LINK_SHARES', True),
                delete_capability=fileserver_info['DELETE'],
                valid_till=timezone.now()+datetime.timedelta(seconds=30),
            )

            for shard in fileserver_info['SHARDS_PUBLIC']:
                Fileserver_Cluster_Member_Shard_Link.objects.create(
                    shard_id=shard['shard_id'],
                    member_id=fileserver.id,
                    read=shard['read'],
                    write=shard['write'],
                    allow_link_shares=shard.get('allow_link_shares', True),
                    delete_capability=shard['delete'],
                    ip_read_whitelist=json.dumps(fileserver_info['IP_READ_WHITELIST']),
                    ip_read_blacklist=json.dumps(fileserver_info['IP_READ_BLACKLIST']),
                    ip_write_whitelist=json.dumps(fileserver_info['IP_WRITE_WHITELIST']),
                    ip_write_blacklist=json.dumps(fileserver_info['IP_WRITE_BLACKLIST']),
                )

        if fileserver is None:
            msg = _('Login failed')
            raise exceptions.AuthenticationFailed(msg)

        return fileserver, fileserver

    @staticmethod
    def validate_cluster_shard_access(cluster_id, announced_shards):

        fcsls = Fileserver_Cluster_Shard_Link.objects.filter(cluster_id=cluster_id).only('read', 'write', 'delete_capability', 'allow_link_shares').all()
        shards = {}
        for fcsl in fcsls:
            shards[str(fcsl.shard_id)] = {
                'read': fcsl.read,
                'write': fcsl.write,
                'delete': fcsl.delete_capability,
                'allow_link_shares': fcsl.allow_link_shares,
            }

        for shard in announced_shards:
            if shard['shard_id'] not in shards:
                msg = _('No permission for shard.')
                raise exceptions.AuthenticationFailed(msg)

            if shard['read'] and not shards[shard['shard_id']]['read']:
                msg = _('No read permission for shard.')
                raise exceptions.AuthenticationFailed(msg)

            if shard['write'] and not shards[shard['shard_id']]['write']:
                msg = _('No write permission for shard.')
                raise exceptions.AuthenticationFailed(msg)

            if shard['delete'] and not shards[shard['shard_id']]['delete']:
                msg = _('No write permission for shard.')
                raise exceptions.AuthenticationFailed(msg)

    @staticmethod
    def get_fileserver_validator(request):
        auth = get_authorization_validator_header(request)
        try:
            auth = auth.decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            auth = json.loads(auth)
        except ValueError:
            msg = _('Invalid token header. Incorrect format in token header.')
            raise exceptions.AuthenticationFailed(msg)

        if 'cluster_id' not in auth:
            msg = _('Invalid token header. Token attribute not present.')
            raise exceptions.AuthenticationFailed(msg)

        if 'fileserver_info' not in auth:
            msg = _('Invalid token header. Token attribute not present.')
            raise exceptions.AuthenticationFailed(msg)

        return auth['cluster_id'], auth['fileserver_info']

class TokenAuthenticationAllowInactive(TokenAuthentication):
    allow_inactive = True

class ManagementCommandUser:
    def __init__(self, pk):
        self.pk = pk
    is_authenticated = True
    secret_key = None

class ManagementCommandAuthentication(BaseAuthentication):

    def authenticate(self, request):
        management_command_access_key = self.get_management_command_access_key(request)

        if not management_command_access_key or not constant_time_compare(management_command_access_key, settings.MANAGEMENT_COMMAND_ACCESS_KEY):
            msg = _('Invalid access key')
            raise exceptions.AuthenticationFailed(msg)

        management_command_user = ManagementCommandUser(management_command_access_key)
        return management_command_user, management_command_user

    @staticmethod
    def get_management_command_access_key(request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'token':
            msg = _('Invalid token header. No token header present.')
            raise exceptions.AuthenticationFailed(msg)

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        return token
