import binascii
import json

from django.conf import settings
from django.urls import reverse
from rest_framework import status

import nacl.encoding
import nacl.signing
import nacl.utils
from nacl.public import PrivateKey

from .base import APITestCaseExtended
from restapi import models


class APIKeyLoginTest(APITestCaseExtended):
    def setUp(self):
        user_private_key = PrivateKey.generate()
        self.user = models.User.objects.create(
            email="api-key-login@example.com",
            email_bcrypt="api-key-login",
            username="api-key-login@example.com",
            authkey="abc",
            public_key=user_private_key.public_key.encode(
                encoder=nacl.encoding.HexEncoder
            ).decode(),
            private_key="a",
            private_key_nonce="a",
            secret_key="a",
            secret_key_nonce="a",
            user_sauce="a",
            is_email_active=True,
        )
        self.signing_key = nacl.signing.SigningKey.generate()
        nonce = nacl.encoding.HexEncoder.encode(
            nacl.utils.random(settings.NONCE_LENGTH_BYTES)
        ).decode()
        self.api_key = models.API_Key.objects.create(
            user=self.user,
            title="Login test",
            public_key="a",
            private_key="a",
            private_key_nonce=nonce,
            secret_key="a",
            secret_key_nonce="1" + nonce[1:],
            user_private_key="a",
            user_private_key_nonce="2" + nonce[1:],
            user_secret_key="a",
            user_secret_key_nonce="3" + nonce[1:],
            verify_key=self.signing_key.verify_key.encode(
                encoder=nacl.encoding.HexEncoder
            ).decode(),
        )

    def test_login_token_is_bound_to_api_key(self):
        session_private_key = PrivateKey.generate()
        info = json.dumps(
            {
                "api_key_id": str(self.api_key.id),
                "session_public_key": session_private_key.public_key.encode(
                    encoder=nacl.encoding.HexEncoder
                ).decode(),
            }
        )
        signature = binascii.hexlify(
            self.signing_key.sign(info.encode()).signature
        ).decode()

        response = self.client.post(
            reverse("api_key_login"), {"info": info, "signature": signature}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        token = models.Token.objects.get(user=self.user)
        self.assertEqual(token.api_key, self.api_key)

    def test_login_rejects_api_key_restricted_to_secrets(self):
        self.api_key.restrict_to_secrets = True
        self.api_key.save()
        session_private_key = PrivateKey.generate()
        info = json.dumps(
            {
                "api_key_id": str(self.api_key.id),
                "session_public_key": session_private_key.public_key.encode(
                    encoder=nacl.encoding.HexEncoder
                ).decode(),
            }
        )
        signature = binascii.hexlify(
            self.signing_key.sign(info.encode()).signature
        ).decode()

        response = self.client.post(
            reverse("api_key_login"), {"info": info, "signature": signature}
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"detail": "API_KEY_RESTRICTED_TO_SECRETS"})
        self.assertFalse(models.Token.objects.filter(user=self.user).exists())
