import json
from datetime import timedelta

import nacl.encoding
from nacl.public import Box, PrivateKey, PublicKey
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.core import mail
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from restapi import models
from restapi.utils import encrypt_with_db_secret
from .base import APITestCaseExtended


@override_settings(
    PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",),
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
class EmergencyLoginTest(APITestCaseExtended):
    def setUp(self):
        self.private_key = PrivateKey.generate()
        self.session_key = PrivateKey.generate()
        self.user = models.User.objects.create(
            username="emergency@example.com",
            email=encrypt_with_db_secret("emergency@example.com"),
            email_bcrypt="emergency",
            public_key=self.private_key.public_key.encode(
                nacl.encoding.HexEncoder
            ).decode(),
            private_key="encrypted-private",
            private_key_nonce="private-nonce",
            secret_key="encrypted-secret",
            secret_key_nonce="secret-nonce",
            user_sauce="sauce",
            is_email_active=True,
        )
        self.emergency = models.Emergency_Code.objects.create(
            user=self.user,
            description="Emergency access",
            emergency_authkey=make_password("emergency-password"),
            emergency_data=b"encrypted-data",
            emergency_data_nonce="nonce",
            emergency_sauce="sauce",
            activation_delay=0,
            activation_date=timezone.now(),
        )
        self.url = reverse("emergency_login")
        self.credentials = {
            "username": self.user.username,
            "emergency_authkey": "emergency-password",
        }

    def activation_payload(self, public_key, device_time=None):
        data = {
            "session_public_key": self.session_key.public_key.encode(
                nacl.encoding.HexEncoder
            ).decode(),
            "device_fingerprint": "test-device",
            "device_description": "Emergency browser",
        }
        if device_time:
            data["device_time"] = device_time
        proof = Box(
            self.private_key, PublicKey(public_key, encoder=nacl.encoding.HexEncoder)
        ).encrypt(json.dumps(data).encode())
        return {
            **self.credentials,
            "update_data": proof.ciphertext.hex(),
            "update_data_nonce": proof.nonce.hex(),
        }

    def test_initial_activation_notifies_and_enforces_waiting_period(self):
        self.emergency.activation_date = None
        self.emergency.activation_delay = 30
        self.emergency.save(update_fields=["activation_date", "activation_delay"])
        response = self.client.post(self.url, self.credentials)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "started")
        self.assertEqual(response.data["remaining_wait_time"], 30)
        self.assertEqual(len(mail.outbox), 1)
        self.emergency.refresh_from_db()
        self.assertIsNotNone(self.emergency.activation_date)
        response = self.client.post(self.url, self.credentials)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "waiting")
        self.assertGreater(response.data["remaining_wait_time"], 0)
        self.assertFalse(models.Token.objects.exists())
        self.emergency.activation_date = timezone.now() - timedelta(seconds=31)
        self.emergency.save(update_fields=["activation_date"])
        response = self.client.post(self.url, self.credentials)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("verifier_public_key", response.data)

    def test_zero_delay_activation_and_notification_without_client_url(self):
        self.emergency.activation_date = None
        self.emergency.save(update_fields=["activation_date"])
        with override_settings(WEB_CLIENT_URL=""):
            response = self.client.post(self.url, self.credentials)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("verifier_public_key", response.data)
        self.assertEqual(len(mail.outbox), 1)

    def test_activation_creates_real_session_and_encrypts_response(self):
        old_token = models.Token.objects.create(user=self.user, active=True)
        response = self.client.post(self.url, self.credentials)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        payload = self.activation_payload(
            response.data["verifier_public_key"], timezone.now().isoformat()
        )
        with override_settings(ALLOW_MULTIPLE_SESSIONS=False):
            response = self.client.put(self.url, payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(models.Token.objects.filter(pk=old_token.pk).exists())
        token = models.Token.objects.get(user=self.user)
        self.assertTrue(token.active)
        self.assertTrue(token.is_emergency_session)
        self.assertEqual(token.device_fingerprint, "test-device")
        self.assertIsNotNone(token.client_date)
        clear = json.loads(
            Box(
                self.session_key,
                PublicKey(settings.PUBLIC_KEY, encoder=nacl.encoding.HexEncoder),
            ).decrypt(
                nacl.encoding.HexEncoder.decode(response.data["login_info"]),
                nacl.encoding.HexEncoder.decode(response.data["login_info_nonce"]),
            )
        )
        self.assertEqual(clear["user_id"], str(self.user.id))
        self.assertEqual(clear["user_email"], "emergency@example.com")
        self.emergency.refresh_from_db()
        self.assertEqual(self.emergency.verifier, "")
        self.assertIsNone(self.emergency.verifier_issue_date)

    def test_activation_rejects_unknown_user(self):
        ready = self.client.post(self.url, self.credentials)
        payload = self.activation_payload(ready.data["verifier_public_key"])
        self.assertEqual(
            self.client.put(
                self.url, {**payload, "username": "unknown@example.com"}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertFalse(models.Token.objects.exists())

    def test_activation_rejects_wrong_emergency_authkey(self):
        ready = self.client.post(self.url, self.credentials)
        payload = self.activation_payload(ready.data["verifier_public_key"])
        self.assertEqual(
            self.client.put(
                self.url, {**payload, "emergency_authkey": "wrong-password"}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertFalse(models.Token.objects.exists())

    def test_activation_rejects_non_hex_proof(self):
        ready = self.client.post(self.url, self.credentials)
        payload = self.activation_payload(ready.data["verifier_public_key"])
        self.assertEqual(
            self.client.put(
                self.url, {**payload, "update_data": "not-hex"}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertFalse(models.Token.objects.exists())

    def test_activation_rejects_non_hex_nonce(self):
        ready = self.client.post(self.url, self.credentials)
        payload = self.activation_payload(ready.data["verifier_public_key"])
        self.assertEqual(
            self.client.put(
                self.url, {**payload, "update_data_nonce": "not-hex"}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertFalse(models.Token.objects.exists())

    def test_activation_rejects_invalid_cryptographic_proof(self):
        ready = self.client.post(self.url, self.credentials)
        payload = self.activation_payload(ready.data["verifier_public_key"])
        self.assertEqual(
            self.client.put(
                self.url, {**payload, "update_data": "00" * 32}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertFalse(models.Token.objects.exists())

    def test_initialization_rejects_missing_credentials(self):
        self.assertEqual(
            self.client.post(self.url, {}).status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertFalse(models.Token.objects.exists())

    def test_initialization_rejects_unknown_user(self):
        self.assertEqual(
            self.client.post(
                self.url,
                {"username": "unknown@example.com", "emergency_authkey": "wrong"},
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertFalse(models.Token.objects.exists())

    def test_initialization_rejects_wrong_emergency_authkey(self):
        self.assertEqual(
            self.client.post(
                self.url, {**self.credentials, "emergency_authkey": "wrong"}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertFalse(models.Token.objects.exists())

    def test_activation_rejects_expired_verifier(self):
        ready = self.client.post(self.url, self.credentials)
        payload = self.activation_payload(ready.data["verifier_public_key"])
        self.emergency.refresh_from_db()
        self.emergency.verifier_issue_date = timezone.now() - timedelta(
            seconds=settings.RECOVERY_VERIFIER_TIME_VALID + 1
        )
        self.emergency.save(update_fields=["verifier_issue_date"])
        self.assertEqual(
            self.client.put(self.url, payload).status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertFalse(models.Token.objects.exists())

    def test_activation_rejects_disabled_account(self):
        ready = self.client.post(self.url, self.credentials)
        payload = self.activation_payload(ready.data["verifier_public_key"])
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.assertEqual(
            self.client.put(self.url, payload).status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertFalse(models.Token.objects.exists())

    def test_activation_rejects_unverified_account(self):
        ready = self.client.post(self.url, self.credentials)
        payload = self.activation_payload(ready.data["verifier_public_key"])
        self.user.is_email_active = False
        self.user.save(update_fields=["is_email_active"])
        self.assertEqual(
            self.client.put(self.url, payload).status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertFalse(models.Token.objects.exists())

    def test_unsupported_read_method(self):
        self.assertEqual(
            self.client.get(self.url).status_code, status.HTTP_405_METHOD_NOT_ALLOWED
        )
