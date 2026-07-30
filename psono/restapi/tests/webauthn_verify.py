import json
from types import SimpleNamespace
from unittest.mock import patch

from webauthn.helpers.exceptions import InvalidAuthenticationResponse

import nacl.encoding

from .base import APITestCaseExtended
from restapi import models
from restapi.serializers.webauthn_verify import WebauthnVerifySerializer
from restapi.utils import encrypt_with_db_secret


class WebauthnVerifySerializerTest(APITestCaseExtended):
    def setUp(self):
        self.user = models.User.objects.create(
            email="webauthn@example.com",
            email_bcrypt="webauthn",
            username="webauthn@example.com",
            authkey="abc",
            public_key="a",
            private_key="a",
            private_key_nonce="a",
            secret_key="a",
            secret_key_nonce="a",
            user_sauce="a",
            is_email_active=True,
        )
        self.token = models.Token.objects.create(user=self.user)
        self.challenge = "single-use-challenge"
        self.credential_id = b"credential-id"
        self.webauthn = models.Webauthn.objects.create(
            user=self.user,
            title="Test authenticator",
            origin="https://example.com",
            rp_id="example.com",
            credential_id=nacl.encoding.HexEncoder.encode(self.credential_id).decode(),
            credential_public_key="00",
            challenge=encrypt_with_db_secret(self.challenge),
            active=True,
        )
        raw_id = nacl.encoding.URLSafeBase64Encoder.encode(self.credential_id).decode()
        self.credential = json.dumps({"rawId": raw_id.rstrip("=")})
        self.request = SimpleNamespace(user=self.user, auth=self.token)

    def get_serializer(self):
        return WebauthnVerifySerializer(
            data={"credential": self.credential}, context={"request": self.request}
        )

    @patch("restapi.serializers.webauthn_verify.verify_authentication_response")
    def test_success_consumes_challenge(self, verify_authentication_response):
        serializer = self.get_serializer()

        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.webauthn.refresh_from_db()
        self.assertEqual(self.webauthn.challenge, "")
        self.assertEqual(
            verify_authentication_response.call_args.kwargs["expected_challenge"],
            self.challenge.encode(),
        )

    @patch("restapi.serializers.webauthn_verify.verify_authentication_response")
    def test_replay_is_rejected(self, verify_authentication_response):
        first_attempt = self.get_serializer()
        self.assertTrue(first_attempt.is_valid(), first_attempt.errors)

        second_attempt = self.get_serializer()
        self.assertFalse(second_attempt.is_valid())
        self.assertEqual(
            second_attempt.errors["non_field_errors"][0],
            "NO_PERMISSION_OR_NOT_EXIST",
        )
        self.assertEqual(verify_authentication_response.call_count, 1)

    @patch(
        "restapi.serializers.webauthn_verify.verify_authentication_response",
        side_effect=InvalidAuthenticationResponse("Invalid assertion"),
    )
    def test_failed_assertion_consumes_challenge(self, verify_authentication_response):
        serializer = self.get_serializer()

        self.assertFalse(serializer.is_valid())
        self.webauthn.refresh_from_db()
        self.assertEqual(self.webauthn.challenge, "")
        verify_authentication_response.assert_called_once()
