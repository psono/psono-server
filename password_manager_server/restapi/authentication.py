from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions
from models import Token
from django.utils.translation import ugettext_lazy as _
from hashlib import sha256


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
    * owner -- The user to which the token belongs
    """

    def authenticate(self, request):
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

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.select_related('owner').get(key=sha256(key).hexdigest())
        except self.model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        if not token.owner.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        if not token.owner.is_email_active:
            raise exceptions.AuthenticationFailed(_('Account not yet verified.'))

        return token.owner, token

    def authenticate_header(self, request):
        return 'Token'