from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions
from .models import Token, User
from django.utils.translation import ugettext_lazy as _
from .utils import get_cache, set_cache
from hashlib import sha512
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from django.core.cache import cache


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

        request.user = user
        user.session_secret_key = token.secret_key

        return user, token

    @staticmethod
    def user_token_to_token_hash(token):
        return sha512(token.encode('utf-8')).hexdigest()

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

    def get_db_token(self, token_hash):

        time_threshold = timezone.now() - timedelta(seconds=settings.TOKEN_TIME_VALID)

        token = get_cache(Token, token_hash)

        if token is None:
            raise exceptions.AuthenticationFailed(_('Invalid token or not yet activated.'))

        if not self.allow_inactive and not token.active:
            raise exceptions.AuthenticationFailed(_('Invalid token or not yet activated.'))

        if token.create_date < time_threshold:
            raise exceptions.AuthenticationFailed(_('Invalid token or not yet activated.'))

        return token

    def authenticate_header(self, request):
        return 'Token'

class TokenAuthenticationAllowInactive(TokenAuthentication):
    allow_inactive = True


