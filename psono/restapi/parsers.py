"""
Parsers are used to parse the content of incoming HTTP requests.

They give us a generic way of being able to handle various media types
on the request, such as form content or json encoded data.
"""
from __future__ import unicode_literals

from rest_framework.parsers import JSONParser
from rest_framework import renderers
from rest_framework.exceptions import ParseError
import nacl.encoding
import nacl.secret
import json

def decrypt(session_secret_key, text_hex, nonce_hex):

    text = nacl.encoding.HexEncoder.decode(text_hex)
    nonce = nacl.encoding.HexEncoder.decode(nonce_hex)

    secret_box = nacl.secret.SecretBox(session_secret_key, encoder=nacl.encoding.HexEncoder)

    return secret_box.decrypt(text, nonce)


class DecryptJSONParser(JSONParser):
    """
    Decrypts data after JSON deserialization.
    """

    media_type = 'application/json'
    renderer_class = renderers.JSONRenderer

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Takes the incoming JSON object, and decrypts the data
        """

        data = super(DecryptJSONParser, self).parse(stream, media_type, parser_context)

        if 'text' not in data or 'nonce' not in data:
            return data

        decrypted_data = decrypt(parser_context['request'].auth.secret_key, data['text'], data['nonce'])

        try:
            data = json.loads(decrypted_data.decode())
        except ValueError:
            raise ParseError('Invalid request')

        return data
