from django.utils.translation import ugettext_lazy as _
from django.utils.six import text_type
from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import HTTP_HEADER_ENCODING, exceptions
from raven.contrib.django.raven_compat.models import client

from hashlib import sha512
import json
import binascii
import dateutil.parser
import datetime

from .parsers import decrypt
from .models import Token, User, Fileserver_Cluster_Members, Fileserver_Cluster, Fileserver_Cluster_Shard_Link, Fileserver_Cluster_Member_Shard_Link
from .utils import get_cache, decrypt_with_db_secret

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
    if isinstance(auth, text_type):
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
                request_device_fingerprint = token_validator.get('request_device_fingerprint', False)
                if not request_device_fingerprint:
                    token.delete()
                    raise exceptions.AuthenticationFailed('Device Fingerprint Protection: request_device_fingerprint missing')
                if str(request_device_fingerprint) != str(token.device_fingerprint):
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

        return user, token

    @staticmethod
    def user_token_to_token_hash(token):
        return sha512(token.encode()).hexdigest()

    @staticmethod
    def get_token_hash(request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'token':
            return None

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
        token_hash = self.get_token_hash(request)

        try:
            fileserver = Fileserver_Cluster_Members.objects.only('pk').get(key=token_hash)
        except Fileserver_Cluster_Members.DoesNotExist:
            cluster_id, fileserver_info_enc = self.get_fileserver_validator(request)
            try:
                cluster = Fileserver_Cluster.objects.get(pk=cluster_id)
            except Fileserver_Cluster.DoesNotExist:
                msg = _('Invalid token header. Cluster ID does not exist.')
                raise exceptions.AuthenticationFailed(msg)

            cluster_public_key = decrypt_with_db_secret(cluster.auth_public_key)

            cluster_crypto_box = Box(PrivateKey(settings.PRIVATE_KEY, encoder=nacl.encoding.HexEncoder),
                                     PublicKey(cluster_public_key, encoder=nacl.encoding.HexEncoder))

            fileserver_info = json.loads(cluster_crypto_box.decrypt(nacl.encoding.HexEncoder.decode(fileserver_info_enc)).decode())

            if fileserver_info['CLUSTER_ID'] != cluster_id:
                msg = _('Invalid fileserver info.')
                raise exceptions.AuthenticationFailed(msg)

            if FileserverAliveAuthentication.user_token_to_token_hash(fileserver_info['FILESERVER_ID']) != token_hash:
                msg = _('Invalid fileserver info.')
                raise exceptions.AuthenticationFailed(msg)

            self.validate_cluster_shard_access(cluster_id, fileserver_info['SHARDS_PUBLIC'])

            fileserver = Fileserver_Cluster_Members.objects.create(
                fileserver_cluster_id=cluster_id,
                key=token_hash,
                public_key=fileserver_info['FILESERVER_PUBLIC_KEY'],
                secret_key=fileserver_info['FILESERVER_SESSION_KEY'],
                url=fileserver_info['HOST_URL'],
                read=fileserver_info['READ'],
                write=fileserver_info['WRITE'],
                delete=fileserver_info['DELETE'],
                valid_till=timezone.now()+datetime.timedelta(seconds=30),
            )

            for shard in fileserver_info['SHARDS_PUBLIC']:
                Fileserver_Cluster_Member_Shard_Link.objects.create(
                    shard_id=shard['shard_id'],
                    member_id=fileserver.id,
                    read=shard['read'],
                    write=shard['write'],
                    delete=shard['delete'],
                    ip_read_whitelist=json.dumps(fileserver_info['IP_READ_WHITELIST']),
                    ip_read_blacklist=json.dumps(fileserver_info['IP_READ_BLACKLIST']),
                    ip_write_whitelist=json.dumps(fileserver_info['IP_WRITE_WHITELIST']),
                    ip_write_blacklist=json.dumps(fileserver_info['IP_WRITE_BLACKLIST']),
                )

        return fileserver, fileserver

    @staticmethod
    def validate_cluster_shard_access(cluster_id, announced_shards):

        fcsls = Fileserver_Cluster_Shard_Link.objects.filter(cluster_id=cluster_id).only('read', 'write', 'delete').all()
        shards = {}
        for fcsl in fcsls:
            shards[str(fcsl.shard_id)] = {
                'read': fcsl.read,
                'write': fcsl.write,
                'delete': fcsl.delete,
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


