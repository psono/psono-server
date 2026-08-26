from django.urls import reverse
from django.conf import settings
from rest_framework import status

import random
import string
import binascii
import os

from restapi import models
from restapi.tests.base import APITestCaseExtended

from .helpers import AdministrativeAccessTestCase


class ReadGroupShareRightTests(APITestCaseExtended):
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

        self.test_group_obj = models.Group.objects.create(
            name="Test Group",
            public_key="a123",
        )

        self.test_group_ob2 = models.Group.objects.create(
            name="Test Group",
            public_key="a123",
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

    def test_read(self):
        """
        Tests GET method
        """

        url = reverse("admin_group_share_right")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class CreateGroupShareRightTests(APITestCaseExtended):
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

    def test_create(self):
        """
        Tests POST method on group share right
        """

        url = reverse("admin_group_share_right")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class UpdateGroupShareRightTests(APITestCaseExtended):
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

        self.test_group_obj = models.Group.objects.create(
            name="Test Group",
            public_key="a123",
        )

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id, data=b"my-data", data_nonce="12345"
        )

        self.test_group_share_right = models.Group_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            group_id=self.test_group_obj.id,
            read=True,
            write=True,
            grant=True,
        )

    def test_update_successful(self):
        """
        Tests PUT method on group share right
        """

        url = reverse("admin_group_share_right")

        data = {
            "group_share_right_id": str(self.test_group_share_right.id),
            "read": False,
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        group = models.Group_Share_Right.objects.get(pk=self.test_group_share_right.id)

        self.assertFalse(group.read)

    def test_update_right_that_doesnt_exist(self):
        """
        Tests PUT method on group share right that doesn't exist
        """

        url = reverse("admin_group_share_right")

        data = {
            "group_share_right_id": "42355067-119f-499c-a67d-15d3cc86f865",
            "read": False,
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_unauthenticated(self):
        """
        Tests PUT method on group share right without authentication
        """

        url = reverse("admin_group_share_right")

        data = {
            "group_share_right_id": str(self.test_group_obj.id),
            "read": False,
        }

        # self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_unauthorized(self):
        """
        Tests PUT method on group share right with a user that is not authorized
        """

        url = reverse("admin_group_share_right")

        data = {
            "group_id": str(self.test_group_obj.id),
            "name": "new name",
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class DeleteGroupShareRightTests(APITestCaseExtended):
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

        self.test_group_obj = models.Group.objects.create(
            name="Test Group",
            public_key="a123",
        )

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id, data=b"my-data", data_nonce="12345"
        )

        self.test_group_share_right = models.Group_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            group_id=self.test_group_obj.id,
            read=True,
            write=True,
            grant=True,
        )

    def test_delete_success(self):
        """
        Tests DELETE method
        """

        url = reverse("admin_group_share_right")

        data = {"group_share_right_id": self.test_group_share_right.id}

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.Group_Share_Right.objects.all().count(), 0)

    def test_delete_unauthorized(self):
        """
        Tests DELETE method on group without being an admin
        """

        url = reverse("admin_group_share_right")

        data = {"group_share_right_id": self.test_group_share_right.id}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_unauthenticated(self):
        """
        Tests DELETE method without authentication
        """

        url = reverse("admin_group_share_right")

        data = {"group_share_right_id": self.test_group_share_right.id}

        # self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_failure_no_group_share_right_id(self):
        """
        Tests DELETE method without a group share right id
        """

        url = reverse("admin_group_share_right")

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_failure_group_share_right_id_not_exist(self):
        """
        Tests DELETE method with a group share right id that does not exist
        """

        url = reverse("admin_group_share_right")

        data = {"group_share_right_id": "499d3c84-e8ae-4a6b-a4c2-43c79beb069a"}

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TenantScopedGroupShareRightTests(AdministrativeAccessTestCase):
    def create_group_share_right(self, group, user):
        share = models.Share.objects.create(
            user=user, data=b"share-data", data_nonce="nonce"
        )
        return models.Group_Share_Right.objects.create(
            creator=user,
            share=share,
            group=group,
            read=True,
            write=True,
            grant=True,
        )

    def test_tenant_scoped_share_right_update_rejects_other_tenant(self):
        right_a = self.create_group_share_right(
            self.create_group("Share Group A", self.tenant_a), self.user_a
        )
        right_b = self.create_group_share_right(
            self.create_group("Share Group B", self.tenant_b), self.user_b
        )
        self.grant("groups.shares.manage")
        self.client.force_authenticate(user=self.delegated_admin)

        response = self.client.put(
            reverse("admin_group_share_right"),
            {"group_share_right_id": right_a.id, "write": False},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.put(
            reverse("admin_group_share_right"),
            {"group_share_right_id": right_b.id, "write": False},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        right_b.refresh_from_db()
        self.assertTrue(right_b.write)

    def test_tenant_scoped_share_right_delete_rejects_other_tenant(self):
        right_a = self.create_group_share_right(
            self.create_group("Share Group A", self.tenant_a), self.user_a
        )
        right_b = self.create_group_share_right(
            self.create_group("Share Group B", self.tenant_b), self.user_b
        )
        self.grant("groups.shares.manage")
        self.client.force_authenticate(user=self.delegated_admin)

        response = self.client.delete(
            reverse("admin_group_share_right"),
            {"group_share_right_id": right_a.id},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.delete(
            reverse("admin_group_share_right"),
            {"group_share_right_id": right_b.id},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(models.Group_Share_Right.objects.filter(pk=right_b.id).exists())
