from django.urls import reverse
from django.conf import settings
from rest_framework import status
from restapi.tests.base import APITestCaseExtended
import random
import string
import binascii
import os
import json
from restapi import models

class ReadInfoTest(APITestCaseExtended):
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
            is_staff=True,
            is_superuser=True
        )

    """
    Test to read info ressource
    """
    def test_read_info_success(self):
        """
        Tests to read all groups
        """

        url = reverse('admin_info')

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get('token_count_user', None), None)
        self.assertNotEqual(response.data.get('token_count_device', None), None)
        self.assertNotEqual(response.data.get('user_count_active', None), None)
        self.assertNotEqual(response.data.get('registrations_over_day', None), None)
        self.assertNotEqual(response.data.get('registrations_over_month', None), None)
        self.assertNotEqual(response.data.get('registrations', None), None)
        self.assertNotEqual(response.data.get('verify_key', None), None)
        self.assertNotEqual(response.data.get('info', None), None)
        self.assertNotEqual(response.data.get('signature', None), None)

        info = json.loads(response.data.get('info'))

        self.assertNotEqual(info.get('web_client', None), None)
        self.assertNotEqual(info.get('version', None), None)
        self.assertNotEqual(info.get('log_audit', None), None)
        self.assertNotEqual(info.get('public_key', None), None)
        self.assertNotEqual(info.get('api', None), None)
        self.assertNotEqual(info.get('authentication_methods', None), None)
        self.assertNotEqual(info.get('management', None), None)

        self.assertEqual(info.get('version', None), settings.VERSION)
        self.assertEqual(info.get('public_key', None), settings.PUBLIC_KEY)
        self.assertEqual(info.get('authentication_methods', None), settings.AUTHENTICATION_METHODS)
        self.assertEqual(info.get('management', None), settings.MANAGEMENT_ENABLED)


    def test_read_info_failure_no_admin(self):
        """
        Tests to read info without admin rights
        """

        url = reverse('admin_info')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_read_info_failure_no_authorization(self):
        """
        Tests to read info without being logged in
        """

        url = reverse('admin_info')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_put_info(self):
        """
        Tests PUT request on info
        """

        url = reverse('admin_info')

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_post_info(self):
        """
        Tests POST request on info
        """

        url = reverse('admin_info')

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_info(self):
        """
        Tests DELETE request on info
        """

        url = reverse('admin_info')

        data = {}

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

