from django.urls import reverse
from django.conf import settings
from rest_framework import status

import random
import string
import binascii
import os

from restapi import models
from restapi.tests.base import APITestCaseExtended


class ReadGroupTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@example.com'
        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@example.com'
        self.test_email_bcrypt = 'a'
        self.test_email_bcrypt2 = 'b'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@psono.pw'
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '6df1f310730e5464ce23e05fa4eca0de3fe30805fc8cc1d6b37389262e4bd9c3'
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
            is_email_active=True
        )


        self.test_group_obj = models.Group.objects.create(
            name = 'Test Group',
            public_key = 'a123',
        )

        self.test_group_ob2 = models.Group.objects.create(
            name = 'Test Group',
            public_key = 'a123',
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
            is_superuser=True
        )


    def test_read_specific_group_success(self):
        """
        Tests GET method on a specific group
        """

        url = reverse('admin_group', kwargs={'group_id': str(self.test_group_obj.id)})

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_read_specific_group_failure_not_exist(self):
        """
        Tests GET method on a specific group
        """

        url = reverse('admin_group', kwargs={'group_id': '6fdbe7bb-b93f-4ef5-817d-7ef9aa7dd9de'})

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_read_specific_group_failure_no_admin_rights(self):
        """
        Tests GET method on group
        """

        url = reverse('admin_group')

        data = {
            'group_id': self.test_group_obj.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_read_group_success(self):
        """
        Tests GET method on group
        """

        url = reverse('admin_group')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['groups']), 2)


    def test_read_group_failure_without_admin_privileges(self):
        """
        Tests GET method on group
        """

        url = reverse('admin_group')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

class CreateGroupTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@example.com'
        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@example.com'
        self.test_email_bcrypt = 'a'
        self.test_email_bcrypt2 = 'b'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@psono.pw'
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '6df1f310730e5464ce23e05fa4eca0de3fe30805fc8cc1d6b37389262e4bd9c3'
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
            is_email_active=True
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
            is_superuser=True
        )



    def test_create_group(self):
        """
        Tests POST method on group
        """

        url = reverse('admin_group')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

class UpdateGroupTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@example.com'
        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@example.com'
        self.test_email_bcrypt = 'a'
        self.test_email_bcrypt2 = 'b'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@psono.pw'
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '6df1f310730e5464ce23e05fa4eca0de3fe30805fc8cc1d6b37389262e4bd9c3'
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
            is_email_active=True
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
            is_superuser=True
        )

        self.test_group_obj = models.Group.objects.create(
            name='Test Group',
            public_key='a123',
        )



    def test_update_group(self):
        """
        Tests PUT method on group
        """

        url = reverse('admin_group')

        data = {
            'group_id': str(self.test_group_obj.id),
            'name': "new name",
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        group = models.Group.objects.get(pk=self.test_group_obj.id)

        self.assertEqual(group.name, data['name'])

    def test_update_group_that_doesnt_exist(self):
        """
        Tests PUT method on group that doesn't exist
        """

        url = reverse('admin_group')

        data = {
            'group_id': "42355067-119f-499c-a67d-15d3cc86f865",
            'name': "new name",
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_group_name_too_short(self):
        """
        Tests PUT method on group with a name that is too short
        """

        url = reverse('admin_group')

        data = {
            'group_id': str(self.test_group_obj.id),
            'name': "A",
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_group_name_contains_forbidden_character(self):
        """
        Tests PUT method on group with a name that contains a forbidden character (e.g. @)
        """

        url = reverse('admin_group')

        data = {
            'group_id': str(self.test_group_obj.id),
            'name': "mygroup@example",
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_update_group_unauthenticated(self):
        """
        Tests PUT method on group without authentication
        """

        url = reverse('admin_group')

        data = {
            'group_id': str(self.test_group_obj.id),
            'name': "new name",
        }

        #self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_group_unauthorized(self):
        """
        Tests PUT method on group with a user that is not authorized
        """

        url = reverse('admin_group')

        data = {
            'group_id': str(self.test_group_obj.id),
            'name': "new name",
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

class DeleteGroupTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@example.com'
        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@example.com'
        self.test_email_bcrypt = 'a'
        self.test_email_bcrypt2 = 'b'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@psono.pw'
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '6df1f310730e5464ce23e05fa4eca0de3fe30805fc8cc1d6b37389262e4bd9c3'
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
            is_email_active=True
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
            is_superuser=True
        )


        self.test_group_obj = models.Group.objects.create(
            name = 'Test Group',
            public_key = 'a123',
        )

        self.test_group_ob2 = models.Group.objects.create(
            name = 'Test Group',
            public_key = 'a123',
        )


    def test_delete_group_success(self):
        """
        Tests DELETE method on group
        """

        url = reverse('admin_group')

        data = {
            'group_id': self.test_group_obj.id
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.Duo.objects.all().count(), 0)


    def test_delete_group_failure_no_admin(self):
        """
        Tests DELETE method on group without being an admin
        """

        url = reverse('admin_group')

        data = {
            'group_id': self.test_group_obj.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_delete_group_failure_no_group_id(self):
        """
        Tests DELETE method on group without a group id
        """

        url = reverse('admin_group')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_group_failure_group_id_not_exist(self):
        """
        Tests DELETE method on group with a group id that does not exist
        """

        url = reverse('admin_group')

        data = {
            'group_id': '499d3c84-e8ae-4a6b-a4c2-43c79beb069a'
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)