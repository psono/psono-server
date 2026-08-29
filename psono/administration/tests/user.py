from django.urls import reverse
from django.conf import settings
from django.db import IntegrityError
from rest_framework import status

import random
import string
import binascii
import os
from mock import patch

from restapi.utils import encrypt_with_db_secret
from restapi.utils import create_user as create_user_util
from restapi import models
from restapi.tests.base import APITestCaseExtended

from .helpers import AdministrativeAccessTestCase, create_user


class ReadUserTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = encrypt_with_db_secret(
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@example.com"
        )
        self.test_email2 = encrypt_with_db_secret(
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

    def test_read_specific_user_success(self):
        """
        Tests GET method on a specific user
        """

        url = reverse("admin_user", kwargs={"user_id": str(self.test_user_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["language"], self.test_user_obj.language)

    def test_read_specific_user_failure_not_exist(self):
        """
        Tests GET method on a specific user
        """

        url = reverse(
            "admin_user", kwargs={"user_id": "6fdbe7bb-b93f-4ef5-817d-7ef9aa7dd9de"}
        )

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_specific_user_failure_no_admin_rights(self):
        """
        Tests GET method on user
        """

        url = reverse("admin_user", kwargs={"user_id": str(self.test_user_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_read_user_success(self):
        """
        Tests GET method on user
        """

        url = reverse("admin_user")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["users"]), 2)

    def test_read_user_failure_without_admin_privileges(self):
        """
        Tests GET method on user
        """

        url = reverse("admin_user")

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class CreateUserTests(APITestCaseExtended):
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

    def test_successful(self):
        """
        Tests to create a user
        """

        url = reverse("admin_user")

        data = {
            "username": "".join(
                random.choice(string.ascii_lowercase) for _ in range(10)
            )
            + "test1@psono.pw",
            "email": "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@example.com",
            "password": "123456",
            "language": "de",
            "require_password_change": True,
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(models.User.objects.filter(username=data["username"]).exists())
        user = models.User.objects.get(username=data["username"])
        self.assertEqual(user.language, data["language"])
        self.assertTrue(user.require_password_change)

    @patch("administration.views.user.create_user")
    def test_successful_with_require_password_change_false(self, mocked_create_user):
        """
        Tests to create a user with require_password_change explicitly disabled
        """

        def create_user_with_required_password_change(*args, **kwargs):
            user_details = create_user_util(*args, **kwargs)
            user_details["user"].require_password_change = True
            user_details["user"].save(update_fields=["require_password_change"])
            return user_details

        mocked_create_user.side_effect = create_user_with_required_password_change

        url = reverse("admin_user")

        data = {
            "username": "".join(
                random.choice(string.ascii_lowercase) for _ in range(10)
            )
            + "test1@psono.pw",
            "email": "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@example.com",
            "password": "123456",
            "require_password_change": False,
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = models.User.objects.get(username=data["username"])
        self.assertFalse(user.require_password_change)


class UpdateUserTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@example.com"
        )
        self.test_email3 = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test2@example.com"
        )
        self.test_email_bcrypt = "d"
        self.test_email_bcrypt3 = "e"
        self.test_username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@psono.pw"
        )
        self.test_username3 = (
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
        self.test_private_key_nonce3 = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        self.test_secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        self.test_secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        self.test_secret_key_nonce3 = binascii.hexlify(
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

        self.test_email2 = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test@example.com"
        )
        self.test_email_bcrypt2 = "b"
        self.test_username2 = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test@psono.pw"
        )
        self.test_authkey2 = binascii.hexlify(
            os.urandom(settings.AUTH_KEY_LENGTH_BYTES)
        ).decode()
        self.test_public_key2 = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        self.test_private_key2 = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        self.test_private_key_nonce2 = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        self.test_secret_key2 = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        self.test_user_sauce2 = (
            "a67fef1ff29eb8f866feaccad336fc6311fa4c71bc183b14c8fceff7416add99"
        )

        self.test_user_obj2 = models.User.objects.create(
            username=self.test_username2,
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            authkey="abc",
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True,
        )

        self.admin = models.User.objects.create(
            email=self.test_email3,
            email_bcrypt=self.test_email_bcrypt3,
            username=self.test_username3,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce3,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce3,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            is_staff=True,
            is_superuser=True,
        )

    def test_update_user_success(self):
        """
        Tests Update user
        """

        url = reverse("admin_user")

        data = {"user_id": self.test_user_obj.id}

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_user_email_success(self):
        """
        Tests Update user
        """

        url = reverse("admin_user")

        data = {
            "user_id": self.test_user_obj.id,
            "email": "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@example.com",
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_user_require_password_change_true(self):
        """
        Tests Update user require_password_change to true
        """

        url = reverse("admin_user")

        data = {
            "user_id": self.test_user_obj.id,
            "require_password_change": True,
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.test_user_obj.refresh_from_db()
        self.assertTrue(self.test_user_obj.require_password_change)

    def test_update_user_require_password_change_false(self):
        """
        Tests Update user require_password_change to false
        """

        self.test_user_obj.require_password_change = True
        self.test_user_obj.save()

        url = reverse("admin_user")

        data = {
            "user_id": self.test_user_obj.id,
            "require_password_change": False,
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.test_user_obj.refresh_from_db()
        self.assertFalse(self.test_user_obj.require_password_change)

    def test_update_user_language_success(self):
        """
        Tests Update user language
        """

        url = reverse("admin_user")

        data = {
            "user_id": self.test_user_obj.id,
            "language": "de",
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.test_user_obj.refresh_from_db()
        self.assertEqual(self.test_user_obj.language, data["language"])

    @patch(
        "administration.serializers.update_user.settings",
        REGISTRATION_EMAIL_FILTER=["example2.com"],
    )
    def test_update_user_email_success_with_email_registration_filter(
        self, patched_registration_email_filter
    ):
        """
        Tests Update user
        """

        url = reverse("admin_user")

        data = {
            "user_id": self.test_user_obj.id,
            "email": "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@example.com",
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_user_email_but_it_already_exists(self):
        """
        Tests Update user email with an email that already exists
        """

        url = reverse("admin_user")

        data = {
            "user_id": self.test_user_obj.id,
            "email": "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "test1@example.com",
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data["user_id"] = self.test_user_obj2.id

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_user_error_user_id_does_not_exist(self):
        """
        Tests Update user that does not exist
        """

        url = reverse("admin_user")

        data = {"user_id": "bdf36a14-052d-400a-8701-1813d542c74c"}

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_user_no_user_id_error(self):
        """
        Tests Update user without user id
        """

        url = reverse("admin_user")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class DeleteUserTests(APITestCaseExtended):
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

    def test_delete_user_success(self):
        """
        Tests DELETE method on user
        """

        url = reverse("admin_user")

        data = {"user_id": self.test_user_obj.id}

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.Duo.objects.all().count(), 0)

    def test_delete_user_failure_no_admin(self):
        """
        Tests DELETE method on user without being an admin
        """

        url = reverse("admin_user")

        data = {"user_id": self.test_user_obj.id}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_user_failure_no_user_id(self):
        """
        Tests DELETE method on user without a user id
        """

        url = reverse("admin_user")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_user_failure_user_id_not_exist(self):
        """
        Tests DELETE method on user with a user id that does not exist
        """

        url = reverse("admin_user")

        data = {"user_id": "499d3c84-e8ae-4a6b-a4c2-43c79beb069a"}

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class AdministrativeUserAccessTests(AdministrativeAccessTestCase):
    def test_is_staff_without_role_is_forbidden(self):
        self.client.force_authenticate(user=self.staff_without_role)
        response = self.client.get(reverse("admin_user"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["detail"], "INSUFFICIENT_PERMISSIONS")

    def test_tenant_scoped_user_list(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(reverse("admin_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            [item["id"] for item in response.data["users"]], [self.user_a.id]
        )

    def test_tenant_scoped_user_list_excludes_protected_administrators(self):
        models.TenantUserMembership.objects.create(
            tenant=self.tenant_a, user=self.superuser, created_by=self.superuser
        )
        protected_admin = create_user("protected-admin")
        models.TenantUserMembership.objects.create(
            tenant=self.tenant_a, user=protected_admin, created_by=self.superuser
        )
        models.AdministrativeRoleAssignment.objects.create(
            role=self.role,
            user=protected_admin,
            is_global=True,
            created_by=self.superuser,
        )
        self.client.force_authenticate(user=self.delegated_admin)

        response = self.client.get(reverse("admin_user"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            [item["id"] for item in response.data["users"]], [self.user_a.id]
        )

    def test_user_detail_nested_memberships_are_capability_and_tenant_scoped(self):
        models.TenantUserMembership.objects.create(
            tenant=self.tenant_b, user=self.user_a, created_by=self.superuser
        )
        group_a = models.Group.objects.create(name="Group A", public_key="public-key")
        group_b = models.Group.objects.create(name="Group B", public_key="public-key")
        models.TenantGroupMembership.objects.create(
            tenant=self.tenant_a, group=group_a, created_by=self.superuser
        )
        models.TenantGroupMembership.objects.create(
            tenant=self.tenant_b, group=group_b, created_by=self.superuser
        )
        models.User_Group_Membership.objects.create(user=self.user_a, group=group_a)
        models.User_Group_Membership.objects.create(user=self.user_a, group=group_b)
        self.client.force_authenticate(user=self.delegated_admin)
        url = reverse("admin_user", kwargs={"user_id": self.user_a.id})

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn("memberships", response.data)
        self.assertEqual(response.data["tenant_ids"], [self.tenant_a.id])

        models.AdministrativeRoleCapability.objects.create(
            role=self.role, capability="groups.memberships.read"
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            [membership["group_id"] for membership in response.data["memberships"]],
            [group_a.id],
        )

    def test_tenant_scoped_user_creation_assigns_ownership(self):
        models.AdministrativeRoleCapability.objects.create(
            role=self.role, capability="users.create"
        )
        self.client.force_authenticate(user=self.delegated_admin)

        with self.settings(DEFAULT_USER_TENANTS=[str(self.tenant_a.id)]):
            response = self.client.post(
                reverse("admin_user"),
                {
                    "username": "created-user@example.com",
                    "email": "created-user@example.com",
                    "password": "password",
                    "tenant_ids": [str(self.tenant_a.id)],
                },
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            models.TenantUserMembership.objects.filter(
                tenant=self.tenant_a, user_id=response.data["id"]
            ).count(),
            1,
        )

    def test_duplicate_user_tenant_scope_returns_bad_request(self):
        models.AdministrativeRoleCapability.objects.create(
            role=self.role, capability="users.create"
        )
        self.client.force_authenticate(user=self.delegated_admin)

        response = self.client.post(
            reverse("admin_user"),
            {
                "username": "duplicate-scope@example.com",
                "email": "duplicate-scope@example.com",
                "password": "password",
                "tenant_ids": [str(self.tenant_a.id), str(self.tenant_a.id)],
            },
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(
            models.User.objects.filter(username="duplicate-scope@example.com").exists()
        )

    def test_shared_user_deletion_requires_confirmation_from_owner(self):
        models.AdministrativeRoleCapability.objects.create(
            role=self.role, capability="users.delete"
        )
        models.TenantUserMembership.objects.create(
            tenant=self.tenant_b, user=self.user_a, created_by=self.superuser
        )
        self.client.force_authenticate(user=self.delegated_admin)
        url = reverse("admin_user")

        response = self.client.delete(url, {"user_id": self.user_a.id})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(models.User.objects.filter(pk=self.user_a.id).exists())

        response = self.client.delete(
            url,
            {"user_id": self.user_a.id, "confirm_shared_ownership": True},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(models.User.objects.filter(pk=self.user_a.id).exists())

    def test_out_of_scope_user_is_not_disclosed(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(
            reverse("admin_user", kwargs={"user_id": self.user_b.id})
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_operation_capability_returns_bad_request(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.put(
            reverse("admin_user"), {"user_id": self.user_a.id, "is_active": False}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.user_a.refresh_from_db()
        self.assertTrue(self.user_a.is_active)

    def test_admin_user_creation_rolls_back_when_tenant_membership_fails(self):
        models.AdministrativeRoleCapability.objects.create(
            role=self.role, capability="users.create"
        )
        self.client.force_authenticate(user=self.delegated_admin)
        username = "rolled-back-user@example.com"

        with (
            patch(
                "administration.views.user.TenantUserMembership.objects.bulk_create",
                side_effect=IntegrityError,
            ),
            self.assertRaises(IntegrityError),
        ):
            self.client.post(
                reverse("admin_user"),
                {
                    "username": username,
                    "email": username,
                    "password": "password",
                    "tenant_ids": [self.tenant_a.id],
                },
            )

        self.assertFalse(models.User.objects.filter(username=username).exists())

    def test_tenant_scoped_user_creation_rejects_out_of_scope_tenant(self):
        self.grant("users.create")
        self.client.force_authenticate(user=self.delegated_admin)
        username = "out-of-scope-user@example.com"

        response = self.client.post(
            reverse("admin_user"),
            {
                "username": username,
                "email": username,
                "password": "password",
                "tenant_ids": [self.tenant_b.id],
            },
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(models.User.objects.filter(username=username).exists())

    def test_tenant_scoped_user_update_allows_own_and_rejects_other_tenant(self):
        self.grant("users.update")
        self.client.force_authenticate(user=self.delegated_admin)

        response = self.client.put(
            reverse("admin_user"),
            {"user_id": self.user_a.id, "is_active": False},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.put(
            reverse("admin_user"),
            {"user_id": self.user_b.id, "is_active": False},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.user_b.refresh_from_db()
        self.assertTrue(self.user_b.is_active)

    def test_tenant_scoped_user_delete_allows_own_and_rejects_other_tenant(self):
        self.grant("users.delete")
        user_a = create_user("delete-user-a")
        models.TenantUserMembership.objects.create(
            tenant=self.tenant_a, user=user_a, created_by=self.superuser
        )
        self.client.force_authenticate(user=self.delegated_admin)

        response = self.client.delete(reverse("admin_user"), {"user_id": user_a.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.delete(
            reverse("admin_user"), {"user_id": self.user_b.id}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(models.User.objects.filter(pk=self.user_b.id).exists())
