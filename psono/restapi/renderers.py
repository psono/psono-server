from __future__ import unicode_literals

from rest_framework.renderers import JSONRenderer, StaticHTMLRenderer

from rest_framework.settings import api_settings
from rest_framework.utils import encoders
from restapi.utils import encrypt_symmetric


class PlainJSONRenderer(StaticHTMLRenderer):
    media_type = 'application/json'
    format = 'json'
    charset = 'utf-8'


class EncryptJSONRenderer(JSONRenderer):
    """
    Renderer which encrypts JSON serialized objects.
    """

    media_type = 'application/json'
    format = 'json'
    encoder_class = encoders.JSONEncoder
    ensure_ascii = not api_settings.UNICODE_JSON
    compact = api_settings.COMPACT_JSON

    # We don't set a charset because JSON is a binary encoding,
    # that can be encoded as utf-8, utf-16 or utf-32.
    # See: http://www.ietf.org/rfc/rfc4627.txt
    # Also: http://lucumr.pocoo.org/2013/7/19/application-mimetypes-and-encodings/
    charset = None

    def render(self, data, accepted_media_type=None, renderer_context=None):
        """
        Render `data` into JSON, returning a bytestring.
        """
        decrypted_data = super(EncryptJSONRenderer, self).render(data, accepted_media_type, renderer_context)
        if renderer_context['request'].auth is None:
            return decrypted_data

        if decrypted_data == b'':
            return decrypted_data

        if not renderer_context['request'].auth.secret_key:
            return decrypted_data

        session_secret_key = renderer_context['request'].auth.secret_key

        encrypted_data = encrypt_symmetric(session_secret_key, decrypted_data)

        decrypted_data_json = super(EncryptJSONRenderer, self).render(encrypted_data, accepted_media_type, renderer_context)

        return decrypted_data_json
