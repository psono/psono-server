"""
Parsers are used to parse the content of incoming HTTP requests.

They give us a generic way of being able to handle various media types
on the request, such as form content or json encoded data.
"""
from __future__ import unicode_literals

from django.conf import settings
from django.utils import timezone
from rest_framework.parsers import JSONParser
from rest_framework import renderers
from rest_framework.exceptions import AuthenticationFailed, ParseError
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
        except ValueError:
            raise ParseError('Invalid request')

        # TODO Activate later once all clients send the request_device_fingerprint
        # if not settings.DEVICE_PROTECTION_DISABLED:
        #     request_device_fingerprint = data.get('request_device_fingerprint', False)
        #     if not request_device_fingerprint:
        #         stream.auth.delete()
        #         raise AuthenticationFailed('Device Fingerprint Protection: request_device_fingerprint missing')
        #     if str(request_device_fingerprint) != stream.auth.device_fingerprint:
        #         stream.auth.delete()
        #         raise AuthenticationFailed('Device Fingerprint Protection: device_fingerprint mismatch')



        if not settings.REPLAY_PROTECTION_DISABLED:

            client_date = stream.auth.client_date
            create_date = stream.auth.create_date
            request_date = data.get('request_time', False)
            now = timezone.now()

            if not request_date:
                stream.auth.delete()
                raise AuthenticationFailed('Replay Protection: request_time missing')

            request_date = dateutil.parser.parse(request_date)
            time_difference = abs(((client_date - create_date) - (request_date - now)).total_seconds())
            if time_difference > settings.REPLAY_PROTECTION_TIME_DFFERENCE:
                stream.auth.delete()
                raise AuthenticationFailed('Replay Protection: Time difference too big')

        return data
