import base64
import hashlib
import json
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import urlparse
from uuid import uuid4

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from restapi import models
from restapi.utils import decrypt_with_db_secret
from .base import APITestCaseExtended


@override_settings(WEBAUTHN_CHALLENGE_TIME_VALID=90)
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
            webauthn.origin
            if urlparse(webauthn.origin).scheme in ("chrome-extension", "extension")
            and webauthn.rp_id == urlparse(webauthn.origin).netloc
            else webauthn.rp_id
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

    @override_settings(
        ALLOWED_SECOND_FACTORS=[],
        CACHE_ENABLE=True,
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        },
    )
    def test_activation_deletes_inactive_tokens(self):
        self.addCleanup(cache.clear)
        valid_till = timezone.now() + timedelta(minutes=5)
        active_token = models.Token.objects.create(
            user=self.user, active=True, valid_till=valid_till
        )
        inactive_tokens = [
            models.Token.objects.create(user=self.user, valid_till=valid_till),
            models.Token.objects.create(
                user=self.user, google_authenticator_2fa=True, valid_till=valid_till
            ),
        ]
        other_tokens = [
            models.Token.objects.create(
                user=self.other_user, active=active, valid_till=valid_till
            )
            for active in (False, True)
        ]
        self.client.force_authenticate(user=self.user, token=active_token)
        response = self.client.put(
            self.url, {"title": "Security key", "origin": "https://example.com"}
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        for token in inactive_tokens:
            self.assertTrue(models.Token.objects.filter(pk=token.pk).exists())
        webauthn = models.Webauthn.objects.get(pk=response.data["id"])
        response = self.client.post(
            self.url,
            {
                "webauthn_id": webauthn.id,
                "credential": self.registration(webauthn),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertSetEqual(
            set(models.Token.objects.values_list("pk", flat=True)),
            {active_token.pk, *(token.pk for token in other_tokens)},
        )
        for token in inactive_tokens:
            self.assertIsNone(cache.get("psono_token_" + token.pk))

    @override_settings(
        ALLOWED_SECOND_FACTORS=[],
        CACHE_ENABLE=True,
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        },
    )
    def test_invalid_activation_preserves_inactive_tokens(self):
        self.addCleanup(cache.clear)
        valid_till = timezone.now() + timedelta(minutes=5)
        active_token = models.Token.objects.create(
            user=self.user, active=True, valid_till=valid_till
        )
        inactive_tokens = [
            models.Token.objects.create(user=self.user, valid_till=valid_till),
            models.Token.objects.create(
                user=self.user, google_authenticator_2fa=True, valid_till=valid_till
            ),
        ]
        self.client.force_authenticate(user=self.user, token=active_token)
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        for token in inactive_tokens:
            self.assertTrue(models.Token.objects.filter(pk=token.pk).exists())

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

    @override_settings(
        WEB_CLIENT_URL="https://example.com/psono/",
        WEBAUTHN_ADDITIONAL_TRUSTED_ORIGINS=[],
    )
    def test_registration_rejects_unofficial_origin_and_wrong_rp_id(self):
        for origin, rp_id in (
            ("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "example.com"),
            (
                "chrome-extension://eljmjmgjkbmpmfljlmklcfineebidmlo",
                "other.example.com",
            ),
            ("https://example.com", "other.example.com"),
        ):
            with self.subTest(origin=origin, rp_id=rp_id):
                response = self.client.put(
                    self.url, {"title": "Key", "origin": origin, "rp_id": rp_id}
                )
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        WEB_CLIENT_URL="https://example.com/psono/",
        WEBAUTHN_ADDITIONAL_TRUSTED_ORIGINS=[],
    )
    def test_activation_must_finish_in_registration_origin(self):
        response = self.client.put(
            self.url,
            {
                "title": "Key",
                "origin": "chrome-extension://eljmjmgjkbmpmfljlmklcfineebidmlo",
                "rp_id": "example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        webauthn = models.Webauthn.objects.get(pk=response.data["id"])
        response = self.client.post(
            self.url,
            {
                "webauthn_id": str(webauthn.id),
                "credential": self.registration(
                    webauthn,
                    "moz-extension://ofcjppepgijefpoodofipcbkfnbnkgghlndbaocdngagmdgooiejchclkancledi",
                ),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        WEB_CLIENT_URL="https://example.com/psono/",
        WEBAUTHN_ADDITIONAL_TRUSTED_ORIGINS=[],
    )
    def test_registration_remains_compatible_with_old_clients_with_existing_keys(self):
        models.Webauthn.objects.create(
            user=self.user,
            origin="https://example.com",
            rp_id="example.com",
            credential_id=b"test-credential".hex(),
            active=True,
        )
        for origin, expected_rp_id in (
            ("https://example.com", "example.com"),
            (
                "chrome-extension://eljmjmgjkbmpmfljlmklcfineebidmlo",
                "eljmjmgjkbmpmfljlmklcfineebidmlo",
            ),
        ):
            with self.subTest(origin=origin):
                # Old clients send no rp_id and do not decode exclusion IDs.
                response = self.client.put(self.url, {"title": "Key", "origin": origin})
                self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                self.assertEqual(response.data["options"]["rp"]["id"], expected_rp_id)
                self.assertEqual(
                    response.data["options"].get("excludeCredentials", []), []
                )

    @override_settings(
        WEB_CLIENT_URL="https://api.example.com",
        WEBAUTHN_ADDITIONAL_TRUSTED_ORIGINS=["moz-extension://" + "a" * 64],
    )
    def test_firefox_extension_registration_and_activation(self):
        origin = "moz-extension://" + "a" * 64
        response = self.client.put(
            self.url,
            {"title": "Firefox key", "origin": origin, "rp_id": "api.example.com"},
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["options"]["rp"]["id"], "api.example.com")
        webauthn = models.Webauthn.objects.get(pk=response.data["id"])
        self.assertEqual(webauthn.origin, origin)
        self.assertEqual(webauthn.rp_id, "api.example.com")
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

    def test_firefox_registration_requires_domain_rp_id(self):
        for rp_id in (None, "https://api.example.com", "example.com/path"):
            with self.subTest(rp_id=rp_id):
                data = {"title": "Firefox key", "origin": "moz-extension://" + "a" * 64}
                if rp_id is not None:
                    data["rp_id"] = rp_id
                response = self.client.put(self.url, data)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertIn("rp_id", response.data)

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

    def test_registration_activation_enforces_the_90_second_creation_boundary(self):
        issued_at = timezone.now()
        for elapsed, expected in (
            (timedelta(seconds=89), status.HTTP_200_OK),
            (timedelta(seconds=90), status.HTTP_400_BAD_REQUEST),
            (timedelta(minutes=10), status.HTTP_400_BAD_REQUEST),
        ):
            with self.subTest(elapsed=elapsed):
                with patch("django.utils.timezone.now", return_value=issued_at):
                    response = self.client.put(
                        self.url, {"title": "Key", "origin": "https://example.com"}
                    )
                self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                webauthn = models.Webauthn.objects.get(pk=response.data["id"])
                credential = self.registration(webauthn)
                # A subsequent write must not extend registration's lifetime.
                models.Webauthn.objects.filter(pk=webauthn.pk).update(
                    write_date=issued_at + elapsed
                )
                with patch(
                    "django.utils.timezone.now", return_value=issued_at + elapsed
                ):
                    response = self.client.post(
                        self.url,
                        {"webauthn_id": str(webauthn.id), "credential": credential},
                    )
                self.assertEqual(response.status_code, expected)
                webauthn.refresh_from_db()
                self.assertEqual(webauthn.active, expected == status.HTTP_200_OK)

    def test_registration_uses_the_configured_lifetime_and_browser_timeout(self):
        issued_at = timezone.now()
        for lifetime in (30, 180):
            with (
                self.subTest(lifetime=lifetime),
                override_settings(WEBAUTHN_CHALLENGE_TIME_VALID=lifetime),
            ):
                for elapsed, expected in (
                    (lifetime - 1, status.HTTP_200_OK),
                    (lifetime, status.HTTP_400_BAD_REQUEST),
                ):
                    with self.subTest(elapsed=elapsed):
                        with patch("django.utils.timezone.now", return_value=issued_at):
                            response = self.client.put(
                                self.url,
                                {"title": "Key", "origin": "https://example.com"},
                            )
                        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                        self.assertEqual(
                            response.data["options"]["timeout"], lifetime * 1000
                        )
                        webauthn = models.Webauthn.objects.get(pk=response.data["id"])
                        credential = self.registration(webauthn)
                        with patch(
                            "django.utils.timezone.now",
                            return_value=issued_at + timedelta(seconds=elapsed),
                        ):
                            response = self.client.post(
                                self.url,
                                {
                                    "webauthn_id": str(webauthn.id),
                                    "credential": credential,
                                },
                            )
                        self.assertEqual(response.status_code, expected)

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
