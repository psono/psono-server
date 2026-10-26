from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from restapi import models
from restapi.utils import encrypt_with_db_secret
from .base import APITestCaseExtended


@override_settings(
    YUBIKEY_CLIENT_ID="123",
    YUBIKEY_SECRET_KEY="T3VoIHlvdSBmb3VuZCBtZT8=",
    ALLOWED_SECOND_FACTORS=[],
    CACHE_ENABLE=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class UserYubikeyOTPTests(APITestCaseExtended):
    def setUp(self):
        self.addCleanup(cache.clear)
        self.user = models.User.objects.create(
            username="mfa-owner@example.com",
            email_bcrypt="owner",
            private_key_nonce="owner-private",
            secret_key_nonce="owner-secret",
            is_email_active=True,
        )
        other_user = models.User.objects.create(
            username="mfa-other@example.com",
            email_bcrypt="mfa-other",
            private_key_nonce="mfa-other-private",
            secret_key_nonce="mfa-other-secret",
            is_email_active=True,
        )
        valid_till = timezone.now() + timedelta(minutes=5)
        self.active_token = models.Token.objects.create(
            user=self.user, active=True, valid_till=valid_till
        )
        self.inactive_tokens = [
            models.Token.objects.create(user=self.user, valid_till=valid_till),
            models.Token.objects.create(
                user=self.user, google_authenticator_2fa=True, valid_till=valid_till
            ),
        ]
        self.other_tokens = [
            models.Token.objects.create(
                user=other_user, active=active, valid_till=valid_till
            )
            for active in (False, True)
        ]
        self.client.force_authenticate(user=self.user, token=self.active_token)

    @patch("restapi.utils.yubikey.Yubico.verify", return_value=True)
    def test_creation_deletes_inactive_tokens(self, verify):
        response = self.client.put(
            reverse("user_yubikey_otp"),
            {"title": "Security key", "yubikey_otp": "c" * 44},
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertSetEqual(
            set(models.Token.objects.values_list("pk", flat=True)),
            {self.active_token.pk, *(token.pk for token in self.other_tokens)},
        )
        for token in self.inactive_tokens:
            self.assertIsNone(cache.get("psono_token_" + token.pk))

    @patch("restapi.utils.yubikey.Yubico.verify", return_value=True)
    def test_activation_deletes_inactive_tokens(self, verify):
        yubikey = models.Yubikey_OTP.objects.create(
            user=self.user,
            yubikey_id=encrypt_with_db_secret("c" * 12),
            active=False,
        )
        response = self.client.post(
            reverse("user_yubikey_otp"),
            {"yubikey_id": yubikey.id, "yubikey_otp": "c" * 44},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertSetEqual(
            set(models.Token.objects.values_list("pk", flat=True)),
            {self.active_token.pk, *(token.pk for token in self.other_tokens)},
        )
        for token in self.inactive_tokens:
            self.assertIsNone(cache.get("psono_token_" + token.pk))

    def test_invalid_setup_preserves_inactive_tokens(self):
        for method in ("put", "post"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(reverse("user_yubikey_otp"), {})
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                for token in self.inactive_tokens:
                    self.assertTrue(models.Token.objects.filter(pk=token.pk).exists())
