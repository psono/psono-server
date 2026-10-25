from datetime import timedelta

import pyotp
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from restapi import models
from restapi.utils import encrypt_with_db_secret
from .base import APITestCaseExtended


@override_settings(
    ALLOWED_SECOND_FACTORS=[],
    CACHE_ENABLE=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class UserGATests(APITestCaseExtended):
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

    def test_activation_deletes_inactive_tokens(self):
        secret = pyotp.random_base32()
        authenticator = models.Google_Authenticator.objects.create(
            user=self.user, secret=encrypt_with_db_secret(secret), active=False
        )
        response = self.client.post(
            reverse("user_ga"),
            {
                "google_authenticator_id": authenticator.id,
                "google_authenticator_token": pyotp.TOTP(secret).now(),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertSetEqual(
            set(models.Token.objects.values_list("pk", flat=True)),
            {self.active_token.pk, *(token.pk for token in self.other_tokens)},
        )
        for token in self.inactive_tokens:
            self.assertIsNone(cache.get("psono_token_" + token.pk))

    def test_invalid_activation_preserves_inactive_tokens(self):
        response = self.client.post(reverse("user_ga"), {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        for token in self.inactive_tokens:
            self.assertTrue(models.Token.objects.filter(pk=token.pk).exists())

    def test_unverified_registration_preserves_inactive_tokens(self):
        response = self.client.put(reverse("user_ga"), {"title": "Authenticator"})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        for token in self.inactive_tokens:
            self.assertTrue(models.Token.objects.filter(pk=token.pk).exists())
