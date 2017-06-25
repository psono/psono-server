"""
Parsers are used to parse the content of incoming HTTP requests.

They give us a generic way of being able to handle various media types
on the request, such as form content or json encoded data.
"""
from __future__ import unicode_literals

from django.conf import settings
from django.utils import six
from django.utils import timezone
from rest_framework.parsers import JSONParser
from rest_framework import renderers
from rest_framework.exceptions import ParseError
import nacl.encoding
import nacl.secret
import json
import dateutil.parser

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

        decrypted_data = decrypt(stream.auth.secret_key, data['text'], data['nonce'])

        try:
            data = json.loads(decrypted_data.decode())
        except ValueError as exc:
            raise ParseError('JSON parse error - %s' % six.text_type(exc))

        client_date = stream.auth.client_date
        create_date = stream.auth.create_date
        request_date = data.get('request_time', False)
        now = timezone.now()

        # TODO Remove first "if clause", once all clients migrated
        if client_date is not None and request_date != False:
            request_date = dateutil.parser.parse(request_date)
            time_difference = abs(((client_date - create_date) - (request_date - now)).total_seconds())
            if time_difference > settings.REPLAY_PROTECTION_TIME_DFFERENCE:
                raise ParseError('Replay Protection: Time difference too big')


        return data
