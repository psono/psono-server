from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions
from models import Token
from django.utils.translation import ugettext_lazy as _
from hashlib import sha512
from django.utils import timezone
from django.conf import settings
from datetime import timedelta


class TokenAuthentication(BaseAuthentication):
    """
    Token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:

        Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a
    """

    model = Token
    """
    A custom token model may be used, but must have the following properties.

    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    def authenticate(self, request):
        token_hash = self.get_token_hash(request)
        return self.authenticate_credentials(token_hash)

    @staticmethod
    def user_token_to_token_hash(token):
        return sha512(token).hexdigest()

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

    def authenticate_credentials(self, token_hash):

        time_threshold = timezone.now() - timedelta(seconds=settings.TOKEN_TIME_VALID)

        try:
            token = self.model.objects.select_related('user').get(key=token_hash, create_date__gte=time_threshold, active=True)
        except self.model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token or not yet activated.'))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        if not token.user.is_email_active:
            raise exceptions.AuthenticationFailed(_('Account not yet verified.'))

        return token.user, token

    def authenticate_header(self, request):
        return 'Token'
