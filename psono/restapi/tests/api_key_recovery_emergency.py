from datetime import timedelta

from django.contrib.auth.hashers import check_password, make_password
from django.test.utils import override_settings
from django.urls import reverse
from django.utils import timezone

from rest_framework import status

from restapi import models
from .base import APITestCaseExtended


@override_settings(
    PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
)
class ApiKeyRecoveryEmergencyTests(APITestCaseExtended):
    def setUp(self):
        self.user = models.User.objects.create(
            username="api-key-recovery@example.com",
            authkey="existing-authkey",
            public_key="a123",
            private_key="a123",
            private_key_nonce="a123",
            secret_key="a123",
            secret_key_nonce="a123",
            user_sauce="a123",
            is_email_active=True,
        )
        self.api_key = models.API_Key.objects.create(
            user=self.user,
            title="Write API key",
            public_key="a123",
            private_key="a123",
            private_key_nonce="api-key-private-nonce",
            secret_key="a123",
            secret_key_nonce="api-key-secret-nonce",
            user_private_key="a123",
            user_private_key_nonce="api-key-user-private-nonce",
            user_secret_key="a123",
            user_secret_key_nonce="api-key-user-secret-nonce",
            verify_key="a123",
            read=True,
            write=True,
        )
        self.token = models.Token.objects.create(
            user=self.user,
            api_key=self.api_key,
            read=True,
            write=True,
            active=True,
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.recovery = models.Recovery_Code.objects.create(
            user=self.user,
            recovery_authkey=make_password("old-key"),
            recovery_data=b"a123",
            recovery_data_nonce="old-recovery-nonce",
            recovery_sauce="a123",
        )
        self.emergency = models.Emergency_Code.objects.create(
            user=self.user,
            description="existing",
            activation_delay=3600,
            emergency_authkey=make_password("old-key"),
            emergency_data=b"a123",
            emergency_data_nonce="old-emergency-nonce",
            emergency_sauce="a123",
        )
        self.recovery_data = {
            "recovery_authkey": "attacker-key",
            "recovery_data": "a123",
            "recovery_data_nonce": "a1b2c3d4",
            "recovery_sauce": "a123",
        }
        self.emergency_data = {
            "description": "new",
            "activation_delay": 3600,
            "emergency_authkey": "attacker-key",
            "emergency_data": "a123",
            "emergency_data_nonce": "b1c2d3e4",
            "emergency_sauce": "a123",
        }

    def authenticate_api_key(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token.clear_text_key}")

    def test_write_api_key_cannot_replace_recovery_credentials_by_default(self):
        self.api_key.allow_emergency_access = True
        self.api_key.save()
        self.authenticate_api_key()
        response = self.client.post(reverse("recoverycode"), self.recovery_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"detail": "API_KEY_SESSION_NOT_ALLOWED"})
        self.assertTrue(
            models.Recovery_Code.objects.filter(pk=self.recovery.pk).exists()
        )

    def test_recovery_permission_allows_replacement_without_current_authkey(self):
        self.api_key.allow_recovery_access = True
        self.api_key.save()
        self.authenticate_api_key()
        response = self.client.post(reverse("recoverycode"), self.recovery_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        replacement = models.Recovery_Code.objects.get(user=self.user)
        self.assertNotEqual(replacement.pk, self.recovery.pk)
        self.assertTrue(check_password("attacker-key", replacement.recovery_authkey))
        self.assertEqual(self.user.authkey, "existing-authkey")

        self.api_key.allow_recovery_access = False
        self.api_key.save()
        self.assertEqual(
            self.client.post(reverse("recoverycode"), self.recovery_data).status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_emergency_code_access_requires_its_own_permission(self):
        self.api_key.allow_recovery_access = True
        self.api_key.save()
        self.authenticate_api_key()
        url = reverse("emergencycode")

        for response in (
            self.client.get(url),
            self.client.post(url, self.emergency_data),
            self.client.delete(url, {"emergency_code_id": self.emergency.pk}),
        ):
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            self.assertEqual(response.data, {"detail": "API_KEY_SESSION_NOT_ALLOWED"})
        self.assertEqual(models.Emergency_Code.objects.count(), 1)

        self.api_key.allow_emergency_access = True
        self.api_key.save()
        self.assertEqual(self.client.get(url).status_code, status.HTTP_200_OK)
        self.assertEqual(
            self.client.post(url, self.emergency_data).status_code,
            status.HTTP_201_CREATED,
        )
        self.assertEqual(
            self.client.delete(
                url, {"emergency_code_id": self.emergency.pk}
            ).status_code,
            status.HTTP_200_OK,
        )

    def test_regular_session_can_manage_codes(self):
        self.client.force_authenticate(user=self.user)
        self.assertEqual(
            self.client.post(reverse("recoverycode"), self.recovery_data).status_code,
            status.HTTP_200_OK,
        )
        self.assertEqual(
            self.client.get(reverse("emergencycode")).status_code,
            status.HTTP_200_OK,
        )
