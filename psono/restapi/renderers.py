from __future__ import unicode_literals

import nacl.encoding
import nacl.utils
import nacl.secret
from rest_framework.renderers import JSONRenderer, StaticHTMLRenderer

from rest_framework.settings import api_settings
from rest_framework.utils import encoders


def encrypt(secret_key, msg):
    """
    Encrypts a message with a secret hex encoded key and an automatically generated random nonce

    :param secret_key: hex encoded secret key
    :type secret_key: str or bytearray
    :param msg: The message to encrypt
    :type msg: bytearray

    :return: The encrypted value
    :rtype: dict
    """
    # generate random nonce
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    # open crypto box with session secret
    secret_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)

    # encrypt msg with crypto box and nonce
    encrypted = secret_box.encrypt(msg, nonce)

    # cut away the nonce
    text = encrypted[len(nonce):]

    # convert nonce and encrypted msg to hex
    nonce_hex = nacl.encoding.HexEncoder.encode(nonce)
    text_hex = nacl.encoding.HexEncoder.encode(text)

    return {'text': text_hex, 'nonce': nonce_hex}


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

        encrypted_data = encrypt(session_secret_key, decrypted_data)

        decrypted_data_json = super(EncryptJSONRenderer, self).render(encrypted_data, accepted_media_type, renderer_context)

        return decrypted_data_json
