import binascii
import os
from datetime import date, timedelta
from unittest.mock import patch

from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from restapi import models
from restapi.permissions import IsAuthenticated
from restapi.tests.base import APITestCaseExtended


def _random_hex(length_bytes):
    return binascii.hexlify(os.urandom(length_bytes)).decode()


class ForcePasswordChangeGateTests(APITestCaseExtended):
    def setUp(self):
        self.user = models.User.objects.create(
            username=f"{_random_hex(8)}@example.com",
            email=f"{_random_hex(4)}@example.com",
            email_bcrypt=_random_hex(8),
            authkey="abc",
            require_password_change=True,
            public_key=_random_hex(settings.USER_PUBLIC_KEY_LENGTH_BYTES),
            private_key=_random_hex(settings.USER_PRIVATE_KEY_LENGTH_BYTES),
            private_key_nonce=_random_hex(settings.NONCE_LENGTH_BYTES),
            secret_key=_random_hex(settings.USER_SECRET_KEY_LENGTH_BYTES),
            secret_key_nonce=_random_hex(settings.NONCE_LENGTH_BYTES),
            user_sauce=_random_hex(32),
            is_email_active=True,
            is_active=True,
        )

        self.token = models.Token.objects.create(
            user=self.user,
            active=True,
            valid_till=timezone.now() + timedelta(hours=1),
            read=True,
            write=True,
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Token {self.token.clear_text_key}",
        )

    def _request(self, method, url, data=None):
        if method == "GET":
            return self.client.get(url, data or {})
        if method == "POST":
            return self.client.post(url, data or {})
        if method == "PUT":
            return self.client.put(url, data or {})
        if method == "DELETE":
            return self.client.delete(url, data or {})
        raise ValueError("Unsupported method")

    @patch.object(IsAuthenticated, "PASSWORD_CHANGE_GATE_START_DATE", date(2000, 1, 1))
    def test_gate_blocks_non_whitelisted_endpoint(self):
        url = reverse("session_key")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch.object(IsAuthenticated, "PASSWORD_CHANGE_GATE_START_DATE", date(2099, 1, 1))
    def test_gate_not_active_before_rollout_date(self):
        url = reverse("session_key")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch.object(IsAuthenticated, "PASSWORD_CHANGE_GATE_START_DATE", date(2000, 1, 1))
    def test_unflagged_user_not_blocked_when_gate_active(self):
        self.user.require_password_change = False
        self.user.save()

        url = reverse("session_key")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch.object(IsAuthenticated, "PASSWORD_CHANGE_GATE_START_DATE", date(2000, 1, 1))
    def test_second_factor_and_password_change_endpoints_are_allowed(self):
        allowed_operations = [
            ("PUT", reverse("user_update"), {}),
            ("GET", reverse("user_ga"), None),
            ("PUT", reverse("user_ga"), {"title": "My GA"}),
            ("POST", reverse("user_ga"), {}),
            ("DELETE", reverse("user_ga"), {}),
            ("GET", reverse("user_duo"), None),
            ("PUT", reverse("user_duo"), {}),
            ("POST", reverse("user_duo"), {}),
            ("DELETE", reverse("user_duo"), {}),
            ("GET", reverse("user_webauthn"), None),
            ("PUT", reverse("user_webauthn"), {}),
            ("POST", reverse("user_webauthn"), {}),
            ("DELETE", reverse("user_webauthn"), {}),
            ("GET", reverse("user_yubikey_otp"), None),
            ("PUT", reverse("user_yubikey_otp"), {}),
            ("POST", reverse("user_yubikey_otp"), {}),
            ("DELETE", reverse("user_yubikey_otp"), {}),
            ("GET", reverse("user_ivalt"), None),
            ("PUT", reverse("user_ivalt"), {}),
            ("POST", reverse("user_ivalt"), {}),
            ("DELETE", reverse("user_ivalt"), {}),
            ("POST", reverse("authentication_ga_verify"), {}),
            ("POST", reverse("authentication_duo_verify"), {}),
            ("PUT", reverse("authentication_webauthn_verify"), {}),
            ("POST", reverse("authentication_webauthn_verify"), {}),
            ("POST", reverse("authentication_yubikey_otp_verify"), {}),
            ("POST", reverse("authentication_ivalt_verify"), {}),
            ("POST", reverse("authentication_activate_token"), {}),
            ("POST", reverse("authentication_logout"), {}),
        ]

        for method, url, data in allowed_operations:
            response = self._request(method, url, data)
            self.assertNotEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN,
                f"Unexpected 403 for {method} {url}",
            )


class ForcePasswordChangeDefaultTests(APITestCaseExtended):
    def test_user_require_password_change_defaults_to_false(self):
        user = models.User.objects.create(
            username=f"{_random_hex(8)}@example.com",
            email=f"{_random_hex(4)}@example.com",
            email_bcrypt=_random_hex(8),
            authkey="abc",
            public_key=_random_hex(settings.USER_PUBLIC_KEY_LENGTH_BYTES),
            private_key=_random_hex(settings.USER_PRIVATE_KEY_LENGTH_BYTES),
            private_key_nonce=_random_hex(settings.NONCE_LENGTH_BYTES),
            secret_key=_random_hex(settings.USER_SECRET_KEY_LENGTH_BYTES),
            secret_key_nonce=_random_hex(settings.NONCE_LENGTH_BYTES),
            user_sauce=_random_hex(32),
            is_email_active=True,
            is_active=True,
        )

        self.assertFalse(user.require_password_change)
