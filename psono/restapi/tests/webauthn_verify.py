import base64
import hashlib
import json

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from .base import APITestCaseExtended
from restapi import models
from restapi.utils import decrypt_with_db_secret, encrypt_with_db_secret


class WebauthnVerifyTest(APITestCaseExtended):
    def setUp(self):
        self.user = models.User.objects.create(
            username="webauthn@example.com",
            email="",
            email_bcrypt="webauthn",
            public_key="key",
            private_key="key",
            private_key_nonce="private",
            secret_key="key",
            secret_key_nonce="secret",
            user_sauce="sauce",
            is_email_active=True,
        )
        self.token = models.Token.objects.create(
            user=self.user, webauthn_2fa=True, google_authenticator_2fa=True
        )
        self.key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.cose_key = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32), -3: numbers.y.to_bytes(32)}
        )
        self.credential_id = b"test-credential"
        self.webauthn = models.Webauthn.objects.create(
            user=self.user,
            title="Authenticator",
            origin="https://example.com",
            rp_id="example.com",
            credential_id=self.credential_id.hex(),
            credential_public_key=self.cose_key.hex(),
            challenge=encrypt_with_db_secret("challenge"),
            active=True,
        )
        self.url = reverse("authentication_webauthn_verify")
        self.client.force_authenticate(user=self.user, token=self.token)

    def assertion(
        self, challenge="challenge", origin="https://example.com", rp_id="example.com"
    ):
        encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": encode(challenge.encode()),
                "origin": origin,
            }
        ).encode()
        authenticator_data = (
            hashlib.sha256(rp_id.encode()).digest() + b"\x01" + (1).to_bytes(4)
        )
        signature = self.key.sign(
            authenticator_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return json.dumps(
            {
                "id": encode(self.credential_id),
                "rawId": encode(self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": encode(client_data),
                    "authenticatorData": encode(authenticator_data),
                    "signature": encode(signature),
                },
            }
        )

    def test_initialization_persists_challenge_and_limits_credentials(self):
        response = self.client.put(self.url, {"origin": "https://example.com/path"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.webauthn.refresh_from_db()
        self.assertEqual(
            decrypt_with_db_secret(self.webauthn.challenge),
            response.data["options"]["challenge"],
        )
        self.assertEqual(len(response.data["options"]["allowCredentials"]), 1)
        response = self.client.post(
            self.url,
            {"credential": self.assertion(response.data["options"]["challenge"])},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.token.refresh_from_db()
        self.assertFalse(self.token.webauthn_2fa)

    def test_real_assertion_consumes_challenge_and_prevents_replay(self):
        credential = self.assertion()
        response = self.client.post(self.url, {"credential": credential})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.webauthn.refresh_from_db()
        self.assertEqual(self.webauthn.challenge, "")
        self.token.webauthn_2fa = True
        self.token.save(update_fields=["webauthn_2fa"])
        response = self.client.post(self.url, {"credential": credential})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.token.refresh_from_db()
        self.assertTrue(self.token.webauthn_2fa)

    @override_settings(MULTIFACTOR_ENABLED=True)
    def test_multifactor_completion_preserves_other_pending_factors(self):
        response = self.client.post(self.url, {"credential": self.assertion()})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.token.refresh_from_db()
        self.assertFalse(self.token.webauthn_2fa)
        self.assertTrue(self.token.google_authenticator_2fa)

    @override_settings(MULTIFACTOR_ENABLED=False)
    def test_single_factor_completion_clears_other_pending_factors(self):
        response = self.client.post(self.url, {"credential": self.assertion()})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.token.refresh_from_db()
        self.assertFalse(self.token.webauthn_2fa)
        self.assertFalse(self.token.google_authenticator_2fa)

    def test_failed_assertion_consumes_challenge(self):
        response = self.client.post(
            self.url, {"credential": self.assertion(origin="https://attacker.example")}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.webauthn.refresh_from_db()
        self.assertEqual(self.webauthn.challenge, "")
        self.token.refresh_from_db()
        self.assertTrue(self.token.webauthn_2fa)

    def test_inactive_and_missing_credentials_are_rejected(self):
        self.webauthn.active = False
        self.webauthn.save(update_fields=["active"])
        response = self.client.post(self.url, {"credential": self.assertion()})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.webauthn.delete()
        response = self.client.post(self.url, {"credential": self.assertion()})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_duplicate_credentials_are_rejected_without_consuming_challenges(self):
        models.Webauthn.objects.create(
            user=self.user,
            origin=self.webauthn.origin,
            rp_id=self.webauthn.rp_id,
            credential_id=self.webauthn.credential_id,
            credential_public_key=self.webauthn.credential_public_key,
            challenge=encrypt_with_db_secret("other-challenge"),
            active=True,
        )
        response = self.client.post(self.url, {"credential": self.assertion()})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.Webauthn.objects.exclude(challenge="").count(), 2)

    def test_empty_challenge_is_rejected(self):
        self.webauthn.challenge = ""
        self.webauthn.save(update_fields=["challenge"])
        response = self.client.post(self.url, {"credential": self.assertion()})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_extension_origin_assertion(self):
        origin = "chrome-extension://test-extension"
        self.webauthn.origin = origin
        self.webauthn.save(update_fields=["origin"])
        response = self.client.post(
            self.url, {"credential": self.assertion(origin=origin, rp_id=origin)}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_initialization_rejects_missing_origin(self):
        response = self.client.put(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_initialization_rejects_insecure_origin(self):
        response = self.client.put(self.url, {"origin": "http://example.com"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_initialization_rejects_unknown_origin(self):
        response = self.client.put(self.url, {"origin": "https://unknown.example"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verification_rejects_missing_credential(self):
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_is_not_supported(self):
        self.assertEqual(
            self.client.get(self.url).status_code, status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def test_delete_is_not_supported(self):
        self.assertEqual(
            self.client.delete(self.url).status_code, status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def test_head_is_not_supported(self):
        self.assertEqual(
            self.client.head(self.url).status_code, status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def test_authentication_required(self):
        self.client.force_authenticate(user=None)
        self.assertEqual(
            self.client.put(self.url, {"origin": self.webauthn.origin}).status_code,
            status.HTTP_401_UNAUTHORIZED,
        )
