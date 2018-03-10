from django.utils.translation import ugettext_lazy as _
from django.utils.six import text_type
from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import HTTP_HEADER_ENCODING, exceptions

from hashlib import sha512
import json
import dateutil.parser

from .parsers import decrypt
from .models import Token, User
from .utils import get_cache


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


        # TODO Activate later once all clients send the new security header

        # token_validator_encrypted = self.get_token_validator(request)
        # token_validator_json = decrypt(token.secret_key, token_validator_encrypted['text'], token_validator_encrypted['nonce'])
        # token_validator = json.loads(token_validator_json.decode())
        #
        # if not settings.DEVICE_PROTECTION_DISABLED:
        #     request_device_fingerprint = token_validator.get('request_device_fingerprint', False)
        #     if not request_device_fingerprint:
        #         token.delete()
        #         raise exceptions.AuthenticationFailed('Device Fingerprint Protection: request_device_fingerprint missing')
        #     if str(request_device_fingerprint) != token.device_fingerprint:
        #         token.delete()
        #         raise exceptions.AuthenticationFailed('Device Fingerprint Protection: device_fingerprint mismatch')
        # if not settings.REPLAY_PROTECTION_DISABLED:
        #
        #     client_date = token.client_date
        #     create_date = token.create_date
        #     request_date = token_validator.get('request_time', False)
        #     now = timezone.now()
        #
        #     if not request_date:
        #         token.delete()
        #         raise exceptions.AuthenticationFailed('Replay Protection: request_time missing')
        #
        #     request_date = dateutil.parser.parse(request_date)
        #     time_difference = abs(((client_date - create_date) - (request_date - now)).total_seconds())
        #     if time_difference > settings.REPLAY_PROTECTION_TIME_DFFERENCE:
        #         token.delete()
        #         raise exceptions.AuthenticationFailed('Replay Protection: Time difference too big')

        request.user = user
        user.session_secret_key = token.secret_key

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

class TokenAuthenticationAllowInactive(TokenAuthentication):
    allow_inactive = True


