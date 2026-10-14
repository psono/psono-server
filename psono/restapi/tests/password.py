from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from restapi import models
from .base import APITestCaseExtended


class PasswordViewTests(APITestCaseExtended):
    @override_settings(ALLOW_LOST_PASSWORD=False)
    def test_disabled_password_recovery_creates_no_verifier(self):
        user = models.User.objects.create(
            username="recovery@example.com",
            private_key_nonce="private",
            secret_key_nonce="secret",
        )
        recovery = models.Recovery_Code.objects.create(
            user=user, recovery_authkey="authkey"
        )
        original_verifier = recovery.verifier
        response = self.client.post(
            reverse("password"),
            {"username": user.username, "recovery_authkey": "authkey"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(
            "PASSWORD_RESET_HAS_BEEN_DISABLED", response.data["non_field_errors"]
        )
        recovery.refresh_from_db()
        self.assertEqual(recovery.verifier, original_verifier)
