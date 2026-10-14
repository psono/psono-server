from django.urls import reverse
from django.conf import settings
from rest_framework import status
from datetime import timedelta
from django.utils import timezone

import random
import string
import binascii
import os

from restapi import models
from restapi.tests.base import APITestCaseExtended


class StatOsTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@example.com"
        )
        self.test_email2 = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test2@example.com"
        )
        self.test_email_bcrypt = "a"
        self.test_email_bcrypt2 = "b"
        self.test_username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@psono.pw"
        )
        self.test_username2 = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test2@psono.pw"
        )
        self.test_authkey = binascii.hexlify(
            os.urandom(settings.AUTH_KEY_LENGTH_BYTES)
        ).decode()
        self.test_public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        self.test_private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        self.test_private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        self.test_private_key_nonce2 = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        self.test_secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        self.test_secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        self.test_user_sauce = (
            "6df1f310730e5464ce23e05fa4eca0de3fe30805fc8cc1d6b37389262e4bd9c3"
        )
        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
        )

        self.admin = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            is_staff=True,
            is_superuser=True,
        )

    def test_read_requires_statistics_capability(self):
        role = models.AdministrativeRole.objects.create(name="User reader")
        models.AdministrativeRoleCapability.objects.create(
            role=role, capability="users.read"
        )
        models.AdministrativeRoleAssignment.objects.create(
            role=role, user=self.test_user_obj, is_global=True
        )
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_stats_os(self):
        """
        Tests GET method on stats_os
        """

        url = reverse("stats_os")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue("other" in response.data)
        self.assertTrue("linux" in response.data)
        self.assertTrue("windows" in response.data)
        self.assertTrue("mac_os" in response.data)
        self.assertTrue("android" in response.data)
        self.assertTrue("ios" in response.data)

    def test_classifies_windows_session(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="Windows",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["windows"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_classifies_ubuntu_session_as_linux(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="Ubuntu",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["linux"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_classifies_mac_os_session(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="Mac OS",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["mac_os"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_classifies_android_session(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="Android",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["android"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_classifies_samsung_session_as_android(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="SM-G950",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["android"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_classifies_pixel_session_as_android(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="Pixel 8",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["android"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_classifies_oneplus_session_as_android(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="OnePlus",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["android"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_classifies_ios_session(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="iOS",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["ios"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_classifies_ipad_session_as_ipados(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="iPad",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["ipados"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_classifies_unknown_os_session(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="Unknown",
            valid_till=timezone.now() + timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["other"], 1)
        self.assertEqual(sum(response.data.values()), 1)

    def test_excludes_expired_sessions(self):
        models.Token.objects.create(
            user=self.test_user_obj,
            device_description="Windows",
            valid_till=timezone.now() - timedelta(hours=1),
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(reverse("stats_os"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(sum(response.data.values()), 0)

    def test_read_requires_administrative_access(self):
        self.client.force_authenticate(user=self.test_user_obj)
        self.assertEqual(
            self.client.get(reverse("stats_os")).status_code, status.HTTP_403_FORBIDDEN
        )

    def test_create_stats_os(self):
        """
        Tests PUT method on stats_os
        """

        url = reverse("stats_os")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_stats_os(self):
        """
        Tests POST method on stats_os
        """

        url = reverse("stats_os")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_stats_os(self):
        """
        Tests DELETE method on stats_os
        """

        url = reverse("stats_os")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
