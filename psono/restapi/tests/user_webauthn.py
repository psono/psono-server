import base64
import hashlib
import json
from uuid import uuid4

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from restapi import models
from restapi.utils import decrypt_with_db_secret
from .base import APITestCaseExtended


class UserWebauthnTest(APITestCaseExtended):
    def setUp(self):
        self.user = models.User.objects.create(
            username="webauthn-owner@example.com",
            email="",
            email_bcrypt="owner",
            public_key="key",
            private_key="key",
            private_key_nonce="private",
            secret_key="key",
            secret_key_nonce="secret",
            user_sauce="sauce",
            is_email_active=True,
        )
        self.other_user = models.User.objects.create(
            username="webauthn-other@example.com",
            email="",
            email_bcrypt="other",
            private_key_nonce="other-private",
            secret_key_nonce="other-secret",
            is_email_active=True,
        )
        self.url = reverse("user_webauthn")
        self.client.force_authenticate(user=self.user)

    def registration(self, webauthn, origin=None):
        def encode(value):
            return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

        key = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        cose = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: key.x.to_bytes(32), -3: key.y.to_bytes(32)}
        )
        credential_id = b"test-registration"
        rp_id = (
            webauthn.rp_id
            if webauthn.origin.startswith("https://")
            else webauthn.origin
        )
        data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": encode(
                    decrypt_with_db_secret(webauthn.challenge).encode()
                ),
                "origin": origin or webauthn.origin,
            }
        ).encode()
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + b"\x41"
            + bytes(4)
            + bytes(16)
            + len(credential_id).to_bytes(2)
            + credential_id
            + cose
        )
        return json.dumps(
            {
                "id": encode(credential_id),
                "rawId": encode(credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": encode(data),
                    "attestationObject": encode(
                        cbor2.dumps(
                            {"fmt": "none", "attStmt": {}, "authData": auth_data}
                        )
                    ),
                },
            }
        )

    def test_https_registration_and_activation(self):
        response = self.client.put(
            self.url, {"title": "Security key", "origin": "https://example.com"}
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        webauthn = models.Webauthn.objects.get(pk=response.data["id"])
        self.assertFalse(webauthn.active)
        self.assertEqual(
            decrypt_with_db_secret(webauthn.challenge),
            response.data["options"]["challenge"],
        )
        response = self.client.post(
            self.url,
            {
                "webauthn_id": str(webauthn.id),
                "credential": self.registration(webauthn),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        webauthn.refresh_from_db()
        self.assertTrue(webauthn.active)
        self.assertEqual(webauthn.credential_id, b"test-registration".hex())
        self.user.refresh_from_db()
        self.assertTrue(self.user.webauthn_enabled)

    def test_chrome_extension_registration_and_activation(self):
        response = self.client.put(
            self.url,
            {"title": "Security key", "origin": "chrome-extension://test-extension"},
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        webauthn = models.Webauthn.objects.get(pk=response.data["id"])
        response = self.client.post(
            self.url,
            {
                "webauthn_id": str(webauthn.id),
                "credential": self.registration(webauthn),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        webauthn.refresh_from_db()
        self.assertTrue(webauthn.active)
        self.assertTrue(webauthn.credential_public_key)

    def test_edge_extension_registration_and_activation(self):
        response = self.client.put(
            self.url, {"title": "Security key", "origin": "extension://test-extension"}
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        webauthn = models.Webauthn.objects.get(pk=response.data["id"])
        response = self.client.post(
            self.url,
            {
                "webauthn_id": str(webauthn.id),
                "credential": self.registration(webauthn),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        webauthn.refresh_from_db()
        self.assertTrue(webauthn.active)
        self.assertTrue(webauthn.credential_public_key)

    def test_registration_rejects_missing_fields(self):
        self.assertEqual(
            self.client.put(self.url, {}).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_registration_rejects_insecure_origin(self):
        self.assertEqual(
            self.client.put(
                self.url, {"title": "Key", "origin": "http://example.com"}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    @override_settings(ALLOWED_SECOND_FACTORS=["ga"])
    def test_registration_rejects_server_disabled_webauthn(self):
        response = self.client.put(
            self.url, {"title": "Key", "origin": "https://example.com"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("SERVER_NOT_SUPPORT_WEBAUTHN", response.data["non_field_errors"])

    @override_settings(ALLOWED_SECOND_FACTORS=[])
    def test_registration_normalizes_origin_when_all_factors_are_allowed(self):
        self.assertEqual(
            self.client.put(
                self.url, {"title": "Key", "origin": "https://example.com/path"}
            ).status_code,
            status.HTTP_201_CREATED,
        )
        self.assertEqual(models.Webauthn.objects.get().origin, "https://example.com")

    def test_activation_rejects_wrong_origin(self):
        response = self.client.put(
            self.url, {"title": "Key", "origin": "https://example.com"}
        )
        webauthn = models.Webauthn.objects.get(pk=response.data["id"])
        response = self.client.post(
            self.url,
            {
                "webauthn_id": str(webauthn.id),
                "credential": self.registration(webauthn, "https://attacker.example"),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        webauthn.refresh_from_db()
        self.assertFalse(webauthn.active)

    def test_activation_rejects_foreign_authenticator(self):
        response = self.client.put(
            self.url, {"title": "Key", "origin": "https://example.com"}
        )
        webauthn = models.Webauthn.objects.get(pk=response.data["id"])
        credential = self.registration(webauthn)
        webauthn.user = self.other_user
        webauthn.save(update_fields=["user"])
        self.assertEqual(
            self.client.post(
                self.url, {"webauthn_id": str(webauthn.id), "credential": credential}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_activation_rejects_missing_authenticator(self):
        self.assertEqual(
            self.client.post(
                self.url, {"webauthn_id": str(uuid4()), "credential": "{}"}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_activation_rejects_missing_fields(self):
        self.assertEqual(
            self.client.post(self.url, {}).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_list_only_returns_own_public_authenticator_details(self):
        own = models.Webauthn.objects.create(
            user=self.user, title="Own key", active=True
        )
        models.Webauthn.objects.create(
            user=self.other_user, title="Other key", active=True
        )
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["webauthns"],
            [{"id": own.id, "active": True, "title": "Own key"}],
        )

    def test_deleting_last_active_authenticator_disables_factor(self):
        self.user.webauthn_enabled = True
        self.user.save(update_fields=["webauthn_enabled"])
        target = models.Webauthn.objects.create(user=self.user, active=True)
        self.assertEqual(
            self.client.delete(self.url, {"webauthn_id": str(target.id)}).status_code,
            status.HTTP_200_OK,
        )
        self.user.refresh_from_db()
        self.assertFalse(self.user.webauthn_enabled)

    def test_deleting_inactive_authenticator_preserves_factor_state(self):
        self.user.webauthn_enabled = True
        self.user.save(update_fields=["webauthn_enabled"])
        target = models.Webauthn.objects.create(user=self.user, active=False)
        self.assertEqual(
            self.client.delete(self.url, {"webauthn_id": str(target.id)}).status_code,
            status.HTTP_200_OK,
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.webauthn_enabled)

    def test_deleting_one_of_multiple_authenticators_preserves_factor(self):
        self.user.webauthn_enabled = True
        self.user.save(update_fields=["webauthn_enabled"])
        target = models.Webauthn.objects.create(user=self.user, active=True)
        remaining = models.Webauthn.objects.create(user=self.user, active=True)
        self.assertEqual(
            self.client.delete(self.url, {"webauthn_id": str(target.id)}).status_code,
            status.HTTP_200_OK,
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.webauthn_enabled)
        self.assertTrue(models.Webauthn.objects.filter(pk=remaining.id).exists())

    def test_deletion_rejects_foreign_authenticator(self):
        other = models.Webauthn.objects.create(user=self.other_user, active=True)
        self.assertEqual(
            self.client.delete(self.url, {"webauthn_id": str(other.id)}).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertTrue(models.Webauthn.objects.filter(pk=other.id).exists())

    def test_deletion_rejects_missing_authenticator(self):
        self.assertEqual(
            self.client.delete(self.url, {"webauthn_id": str(uuid4())}).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_deletion_rejects_missing_fields(self):
        self.assertEqual(
            self.client.delete(self.url, {}).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_get_requires_authentication(self):
        self.client.force_authenticate(user=None)
        self.assertEqual(
            self.client.get(self.url).status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_put_requires_authentication(self):
        self.client.force_authenticate(user=None)
        self.assertEqual(
            self.client.put(self.url, {}).status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_post_requires_authentication(self):
        self.client.force_authenticate(user=None)
        self.assertEqual(
            self.client.post(self.url, {}).status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_delete_requires_authentication(self):
        self.client.force_authenticate(user=None)
        self.assertEqual(
            self.client.delete(self.url).status_code, status.HTTP_401_UNAUTHORIZED
        )
