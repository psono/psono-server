import base64
import hashlib
import itertools
import json
from datetime import timedelta
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from .base import APITestCaseExtended
from restapi import models
from restapi.utils import decrypt_with_db_secret, encrypt_with_db_secret


WEB_ORIGIN = "https://example.com"
CHROME_ORIGIN = "chrome-extension://eljmjmgjkbmpmfljlmklcfineebidmlo"
EDGE_ORIGIN = "chrome-extension://abobmepfpbkapdlmfhnnkebcnhgeccbm"
FIREFOX_ORIGIN = (
    "moz-extension://ofcjppepgijefpoodofipcbkfnbnkgghlndbaocdngagmdgooiejchclkancledi"
)
CLIENT_ORIGINS = (WEB_ORIGIN, CHROME_ORIGIN, EDGE_ORIGIN, FIREFOX_ORIGIN)
CUSTOM_ORIGIN = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@override_settings(WEBAUTHN_CHALLENGE_TIME_VALID=90)
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
            challenge="",
            active=True,
        )
        self.url = reverse("authentication_webauthn_verify")
        self.client.force_authenticate(user=self.user, token=self.token)
        self.challenge = self.start_attempt()

    def start_attempt(self, origin=WEB_ORIGIN, **kwargs):
        response = self.client.put(self.url, {"origin": origin, **kwargs})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.data["options"]["challenge"]

    def assertion(
        self, challenge=None, origin="https://example.com", rp_id="example.com"
    ):
        if challenge is None:
            challenge = self.challenge
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
        self.assertIn(
            response.data["options"]["challenge"],
            decrypt_with_db_secret(self.webauthn.challenge),
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
        self.webauthn.rp_id = "test-extension"
        self.webauthn.save(update_fields=["origin", "rp_id"])
        challenge = self.start_attempt(origin)
        response = self.client.post(
            self.url,
            {"credential": self.assertion(challenge, origin=origin, rp_id=origin)},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_initialization_rejects_missing_origin(self):
        response = self.client.put(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_firefox_extension_initialization_and_assertion(self):
        origin = "moz-extension://" + "a" * 64
        self.webauthn.origin = origin
        self.webauthn.save(update_fields=["origin"])
        other_rp = models.Webauthn.objects.create(
            user=self.user,
            origin=origin,
            rp_id="other.example.com",
            credential_id=b"other-rp".hex(),
            challenge="unchanged",
            active=True,
        )
        response = self.client.put(self.url, {"origin": origin, "rp_id": "example.com"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["options"]["rpId"], "example.com")
        self.assertEqual(len(response.data["options"]["allowCredentials"]), 1)
        other_rp.refresh_from_db()
        self.assertEqual(other_rp.challenge, "unchanged")
        response = self.client.post(
            self.url,
            {
                "credential": self.assertion(
                    response.data["options"]["challenge"], origin
                )
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.token.refresh_from_db()
        self.assertFalse(self.token.webauthn_2fa)

    def test_firefox_initialization_rejects_unregistered_rp_id(self):
        origin = "moz-extension://" + "a" * 64
        self.webauthn.origin = origin
        self.webauthn.save(update_fields=["origin"])
        response = self.client.put(
            self.url, {"origin": origin, "rp_id": "other.example.com"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_firefox_assertion_rejects_other_extension_origin(self):
        self.webauthn.origin = "moz-extension://" + "a" * 64
        self.webauthn.save(update_fields=["origin"])
        response = self.client.post(
            self.url,
            {"credential": self.assertion(origin="moz-extension://" + "b" * 64)},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.token.refresh_from_db()
        self.assertTrue(self.token.webauthn_2fa)

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

    def test_assertion_cannot_complete_another_tokens_login_or_consume_its_challenge(
        self,
    ):
        credential = self.assertion()
        other_token = models.Token.objects.create(user=self.user, webauthn_2fa=True)
        self.client.force_authenticate(user=self.user, token=other_token)
        response = self.client.post(self.url, {"credential": credential})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        other_token.refresh_from_db()
        self.assertTrue(other_token.webauthn_2fa)
        self.client.force_authenticate(user=self.user, token=self.token)
        response = self.client.post(self.url, {"credential": credential})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_parallel_tokens_can_each_complete_their_own_login(self):
        first_credential = self.assertion()
        other_token = models.Token.objects.create(user=self.user, webauthn_2fa=True)
        self.client.force_authenticate(user=self.user, token=other_token)
        second_challenge = self.start_attempt()
        self.assertNotEqual(second_challenge, self.challenge)
        self.client.force_authenticate(user=self.user, token=self.token)
        response = self.client.post(self.url, {"credential": first_credential})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.client.force_authenticate(user=self.user, token=other_token)
        response = self.client.post(
            self.url, {"credential": self.assertion(second_challenge)}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        other_token.refresh_from_db()
        self.assertFalse(other_token.webauthn_2fa)

    def test_failed_attempt_does_not_consume_another_tokens_challenge(self):
        other_token = models.Token.objects.create(user=self.user, webauthn_2fa=True)
        self.client.force_authenticate(user=self.user, token=other_token)
        other_challenge = self.start_attempt()
        response = self.client.post(
            self.url,
            {"credential": self.assertion(other_challenge, "https://attacker.example")},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.client.force_authenticate(user=self.user, token=self.token)
        response = self.client.post(self.url, {"credential": self.assertion()})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_authentication_enforces_the_exact_90_second_boundary(self):
        issued_at = timezone.now()
        for elapsed, expected in (
            (timedelta(seconds=89, microseconds=999999), status.HTTP_200_OK),
            (timedelta(seconds=90), status.HTTP_400_BAD_REQUEST),
            (timedelta(minutes=10), status.HTTP_400_BAD_REQUEST),
        ):
            with self.subTest(elapsed=elapsed):
                self.token.webauthn_2fa = True
                self.token.save(update_fields=["webauthn_2fa"])
                with patch("django.utils.timezone.now", return_value=issued_at):
                    challenge = self.start_attempt()
                credential = self.assertion(challenge)
                with patch(
                    "django.utils.timezone.now", return_value=issued_at + elapsed
                ):
                    response = self.client.post(self.url, {"credential": credential})
                self.assertEqual(response.status_code, expected)
                self.token.refresh_from_db()
                self.assertEqual(
                    self.token.webauthn_2fa, expected != status.HTTP_200_OK
                )

    def test_expired_write_date_rejects_an_otherwise_valid_challenge(self):
        models.Webauthn.objects.filter(pk=self.webauthn.pk).update(
            write_date=timezone.now() - timedelta(seconds=90)
        )
        response = self.client.post(self.url, {"credential": self.assertion()})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.token.refresh_from_db()
        self.assertTrue(self.token.webauthn_2fa)

    def test_authentication_uses_the_configured_lifetime_and_browser_timeout(self):
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
                        self.token.webauthn_2fa = True
                        self.token.save(update_fields=["webauthn_2fa"])
                        with patch("django.utils.timezone.now", return_value=issued_at):
                            response = self.client.put(self.url, {"origin": WEB_ORIGIN})
                        self.assertEqual(response.status_code, status.HTTP_200_OK)
                        self.assertEqual(
                            response.data["options"]["timeout"], lifetime * 1000
                        )
                        credential = self.assertion(
                            response.data["options"]["challenge"]
                        )
                        with patch(
                            "django.utils.timezone.now",
                            return_value=issued_at + timedelta(seconds=elapsed),
                        ):
                            response = self.client.post(
                                self.url, {"credential": credential}
                            )
                        self.assertEqual(response.status_code, expected)

    @override_settings(WEBAUTHN_CHALLENGE_TIME_VALID=30)
    def test_another_session_cannot_extend_the_configured_lifetime(self):
        issued_at = timezone.now()
        with patch("django.utils.timezone.now", return_value=issued_at):
            first_challenge = self.start_attempt()
        other_token = models.Token.objects.create(user=self.user, webauthn_2fa=True)
        self.client.force_authenticate(user=self.user, token=other_token)
        with patch(
            "django.utils.timezone.now", return_value=issued_at + timedelta(seconds=29)
        ):
            second_challenge = self.start_attempt()
        with patch(
            "django.utils.timezone.now", return_value=issued_at + timedelta(seconds=30)
        ):
            self.client.force_authenticate(user=self.user, token=self.token)
            response = self.client.post(
                self.url, {"credential": self.assertion(first_challenge)}
            )
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.client.force_authenticate(user=self.user, token=other_token)
            response = self.client.post(
                self.url, {"credential": self.assertion(second_challenge)}
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_initialization_refreshes_write_date_for_an_old_credential(self):
        old_date = timezone.now() - timedelta(days=365)
        models.Webauthn.objects.filter(pk=self.webauthn.pk).update(
            create_date=old_date, write_date=old_date
        )
        issued_at = timezone.now()
        with patch("django.utils.timezone.now", return_value=issued_at):
            challenge = self.start_attempt()
        self.webauthn.refresh_from_db()
        self.assertEqual(self.webauthn.create_date, old_date)
        self.assertEqual(self.webauthn.write_date, issued_at)
        response = self.client.post(self.url, {"credential": self.assertion(challenge)})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_another_session_cannot_extend_the_first_sessions_expiry(self):
        issued_at = timezone.now()
        with patch("django.utils.timezone.now", return_value=issued_at):
            first_challenge = self.start_attempt()
        other_token = models.Token.objects.create(user=self.user, webauthn_2fa=True)
        self.client.force_authenticate(user=self.user, token=other_token)
        with patch(
            "django.utils.timezone.now", return_value=issued_at + timedelta(seconds=80)
        ):
            second_challenge = self.start_attempt()
        with patch(
            "django.utils.timezone.now", return_value=issued_at + timedelta(seconds=91)
        ):
            self.client.force_authenticate(user=self.user, token=self.token)
            response = self.client.post(
                self.url, {"credential": self.assertion(first_challenge)}
            )
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.client.force_authenticate(user=self.user, token=other_token)
            response = self.client.post(
                self.url, {"credential": self.assertion(second_challenge)}
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_challenge_is_consumed_across_all_credentials_for_the_same_token(self):
        other_id = b"other-credential"
        models.Webauthn.objects.create(
            user=self.user,
            origin=WEB_ORIGIN,
            rp_id="example.com",
            credential_id=other_id.hex(),
            credential_public_key=self.cose_key.hex(),
            challenge="",
            active=True,
        )
        challenge = self.start_attempt()
        response = self.client.post(self.url, {"credential": self.assertion(challenge)})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.token.webauthn_2fa = True
        self.token.save(update_fields=["webauthn_2fa"])
        self.credential_id = other_id
        response = self.client.post(self.url, {"credential": self.assertion(challenge)})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_pre_upgrade_unbound_challenges_require_reinitialization(self):
        models.Webauthn.objects.filter(pk=self.webauthn.pk).update(
            challenge=encrypt_with_db_secret("old-unbound-challenge")
        )
        response = self.client.post(
            self.url, {"credential": self.assertion("old-unbound-challenge")}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        challenge = self.start_attempt()
        response = self.client.post(self.url, {"credential": self.assertion(challenge)})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(WEBAUTHN_CHALLENGE_TIME_VALID=180)
    def test_session_context_limit_does_not_evict_an_existing_login(self):
        for _ in range(63):
            other_token = models.Token.objects.create(user=self.user, webauthn_2fa=True)
            self.client.force_authenticate(user=self.user, token=other_token)
            self.start_attempt()
        extra_token = models.Token.objects.create(user=self.user, webauthn_2fa=True)
        self.client.force_authenticate(user=self.user, token=extra_token)
        response = self.client.put(self.url, {"origin": WEB_ORIGIN})
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(response["Retry-After"], "180")
        self.client.force_authenticate(user=self.user, token=self.token)
        response = self.client.post(self.url, {"credential": self.assertion()})
        self.assertEqual(response.status_code, status.HTTP_200_OK)


@override_settings(
    WEB_CLIENT_URL="https://example.com/psono/",
    WEBAUTHN_ADDITIONAL_TRUSTED_ORIGINS=[],
)
class SharedWebauthnVerifyTests(WebauthnVerifyTest):
    # The inherited tests also exercise the existing authentication contract
    # with sharing enabled, alongside the new cross-client cases below.

    def registration(self, challenge, origin, rp_id="example.com"):
        encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
        data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": encode(challenge.encode()),
                "origin": origin,
            }
        ).encode()
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + b"\x41"
            + bytes(4)
            + bytes(16)
            + len(self.credential_id).to_bytes(2)
            + self.credential_id
            + self.cose_key
        )
        return json.dumps(
            {
                "id": encode(self.credential_id),
                "rawId": encode(self.credential_id),
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

    def initialize(self, origin, **kwargs):
        return self.client.put(
            self.url, {"origin": origin, "rp_id": "example.com", **kwargs}
        )

    def add_legacy_chrome_credential(self):
        return models.Webauthn.objects.create(
            user=self.user,
            origin=CHROME_ORIGIN,
            rp_id=CHROME_ORIGIN.split("://")[1],
            credential_id=b"legacy-chrome".hex(),
            credential_public_key=self.cose_key.hex(),
            challenge="",
            active=True,
        )

    def test_registration_and_authentication_in_every_client_combination(self):
        registration_url = reverse("user_webauthn")
        for source, target in itertools.product(CLIENT_ORIGINS, repeat=2):
            with self.subTest(source=source, target=target):
                models.Webauthn.objects.filter(user=self.user).delete()
                self.token.webauthn_2fa = True
                self.token.save(update_fields=["webauthn_2fa"])
                response = self.client.put(
                    registration_url,
                    {"title": "Shared key", "origin": source, "rp_id": "example.com"},
                )
                self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                self.assertEqual(response.data["options"]["rp"]["id"], "example.com")
                response = self.client.post(
                    registration_url,
                    {
                        "webauthn_id": str(response.data["id"]),
                        "credential": self.registration(
                            response.data["options"]["challenge"], source
                        ),
                    },
                )
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(
                    models.Webauthn.objects.get(user=self.user).origin, source
                )
                response = self.initialize(target)
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(response.data["options"]["rpId"], "example.com")
                self.assertEqual(len(response.data["options"]["allowCredentials"]), 1)
                response = self.client.post(
                    self.url,
                    {
                        "credential": self.assertion(
                            response.data["options"]["challenge"], target
                        )
                    },
                )
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.token.refresh_from_db()
                self.assertFalse(self.token.webauthn_2fa)

    def test_existing_firefox_domain_credential_works_in_webclient(self):
        self.webauthn.origin = FIREFOX_ORIGIN
        self.webauthn.save(update_fields=["origin"])
        response = self.client.put(self.url, {"origin": WEB_ORIGIN})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.post(
            self.url,
            {"credential": self.assertion(response.data["options"]["challenge"])},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_unofficial_extension_cannot_request_shared_credentials(self):
        response = self.initialize(CUSTOM_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_signed_origin_must_be_trusted_even_if_initialization_claims_official_origin(
        self,
    ):
        response = self.initialize(CHROME_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.post(
            self.url,
            {
                "credential": self.assertion(
                    response.data["options"]["challenge"], CUSTOM_ORIGIN
                )
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.token.refresh_from_db()
        self.assertTrue(self.token.webauthn_2fa)

    def test_unrelated_website_cannot_use_shared_credential(self):
        response = self.initialize("https://attacker.example")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(
            self.url, {"credential": self.assertion(origin="https://attacker.example")}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_untrusted_registration_is_not_adopted_into_the_shared_group(self):
        self.webauthn.origin = CUSTOM_ORIGIN
        self.webauthn.save(update_fields=["origin"])
        response = self.initialize(FIREFOX_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(
            self.url, {"credential": self.assertion(origin=FIREFOX_ORIGIN)}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_initialization_rejects_wrong_rp_id(self):
        response = self.initialize(CHROME_ORIGIN, rp_id="other.example.com")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_signature_rejects_wrong_rp_hash(self):
        response = self.client.post(
            self.url,
            {
                "credential": self.assertion(
                    origin=CHROME_ORIGIN, rp_id="other.example.com"
                )
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_signature_rejects_wrong_private_key(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        response = self.client.post(
            self.url, {"credential": self.assertion(origin=FIREFOX_ORIGIN)}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cross_client_assertion_cannot_be_replayed(self):
        response = self.initialize(FIREFOX_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        credential = self.assertion(
            response.data["options"]["challenge"], CHROME_ORIGIN
        )
        response = self.client.post(self.url, {"credential": credential})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.token.webauthn_2fa = True
        self.token.save(update_fields=["webauthn_2fa"])
        response = self.client.post(self.url, {"credential": credential})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.token.refresh_from_db()
        self.assertTrue(self.token.webauthn_2fa)

    def test_cross_client_assertion_rejects_wrong_challenge(self):
        response = self.initialize(FIREFOX_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.post(
            self.url,
            {"credential": self.assertion("wrong-challenge", CHROME_ORIGIN)},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_shared_credential_still_belongs_only_to_its_user(self):
        other_user = models.User.objects.create(
            username="other-shared@example.com",
            email_bcrypt="other-shared",
            private_key_nonce="other-shared-private",
            secret_key_nonce="other-shared-secret",
            is_email_active=True,
        )
        self.webauthn.user = other_user
        self.webauthn.save(update_fields=["user"])
        response = self.initialize(FIREFOX_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(
            self.url, {"credential": self.assertion(origin=CHROME_ORIGIN)}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_only_legacy_chrome_keys_are_selected_automatically_when_no_shared_keys_exist(
        self,
    ):
        self.webauthn.delete()
        legacy = self.add_legacy_chrome_credential()
        response = self.initialize(CHROME_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["options"]["rpId"], legacy.rp_id)
        self.assertFalse(response.data["legacy_available"])
        self.credential_id = bytes.fromhex(legacy.credential_id)
        response = self.client.post(
            self.url,
            {
                "credential": self.assertion(
                    response.data["options"]["challenge"], CHROME_ORIGIN, CHROME_ORIGIN
                )
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_automatic_legacy_retry_when_shared_and_legacy_keys_both_exist(self):
        legacy = self.add_legacy_chrome_credential()
        response = self.initialize(CHROME_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["options"]["rpId"], "example.com")
        self.assertTrue(response.data["legacy_available"])
        shared_challenge = response.data["options"]["challenge"]
        self.webauthn.refresh_from_db()
        shared_state = self.webauthn.challenge
        response = self.initialize(CHROME_ORIGIN, legacy=True)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["options"]["rpId"], legacy.rp_id)
        self.assertFalse(response.data["legacy_available"])
        self.webauthn.refresh_from_db()
        self.assertEqual(self.webauthn.challenge, shared_state)
        self.assertIn(shared_challenge, decrypt_with_db_secret(shared_state))
        self.credential_id = bytes.fromhex(legacy.credential_id)
        response = self.client.post(
            self.url,
            {
                "credential": self.assertion(
                    response.data["options"]["challenge"], CHROME_ORIGIN, CHROME_ORIGIN
                )
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_old_chrome_client_can_authenticate_without_requesting_an_rp_id(self):
        self.webauthn.delete()
        legacy = self.add_legacy_chrome_credential()
        response = self.client.put(self.url, {"origin": CHROME_ORIGIN})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["options"]["rpId"], legacy.rp_id)
        self.credential_id = bytes.fromhex(legacy.credential_id)
        response = self.client.post(
            self.url,
            {
                "credential": self.assertion(
                    response.data["options"]["challenge"], CHROME_ORIGIN, CHROME_ORIGIN
                )
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_legacy_chrome_key_is_not_shared_with_other_origins(self):
        self.webauthn.delete()
        legacy = self.add_legacy_chrome_credential()
        response = self.initialize(FIREFOX_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.initialize(CHROME_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.credential_id = bytes.fromhex(legacy.credential_id)
        response = self.client.post(
            self.url,
            {
                "credential": self.assertion(
                    response.data["options"]["challenge"], FIREFOX_ORIGIN, CHROME_ORIGIN
                )
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_challenge_updates_exclude_untrusted_inactive_and_other_rp_credentials(
        self,
    ):
        for origin, rp_id, active in (
            (CUSTOM_ORIGIN, "example.com", True),
            (CHROME_ORIGIN, "other.example.com", True),
            (FIREFOX_ORIGIN, "example.com", False),
        ):
            models.Webauthn.objects.create(
                user=self.user,
                origin=origin,
                rp_id=rp_id,
                challenge="unchanged",
                active=active,
            )
        response = self.initialize(FIREFOX_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["options"]["allowCredentials"]), 1)
        self.assertEqual(
            models.Webauthn.objects.filter(challenge="unchanged").count(), 3
        )

    @override_settings(WEBAUTHN_ADDITIONAL_TRUSTED_ORIGINS=[CUSTOM_ORIGIN])
    def test_administrator_can_trust_an_additional_extension(self):
        response = self.initialize(CUSTOM_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.post(
            self.url,
            {
                "credential": self.assertion(
                    response.data["options"]["challenge"], CUSTOM_ORIGIN
                )
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(WEB_CLIENT_URL="", HOST_URL="https://example.com/server")
    def test_host_url_fallback_matches_info_endpoint(self):
        response = self.initialize(FIREFOX_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(WEB_CLIENT_URL="https://EXAMPLE.com:443/psono/")
    def test_webclient_url_is_normalized_to_browser_origin(self):
        response = self.client.put(self.url, {"origin": WEB_ORIGIN})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.initialize(FIREFOX_ORIGIN)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(WEB_CLIENT_URL="https://täst.example/psono/")
    def test_international_webclient_uses_the_browser_ascii_rp_id(self):
        self.webauthn.origin = "https://xn--tst-qla.example"
        self.webauthn.rp_id = "xn--tst-qla.example"
        self.webauthn.save(update_fields=["origin", "rp_id"])
        response = self.initialize(CHROME_ORIGIN, rp_id="xn--tst-qla.example")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["options"]["rpId"], "xn--tst-qla.example")
        response = self.client.post(
            self.url,
            {
                "credential": self.assertion(
                    response.data["options"]["challenge"],
                    CHROME_ORIGIN,
                    "xn--tst-qla.example",
                )
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
