from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework import status

from datetime import timedelta
import random
import string
import binascii
import os

from restapi import models
from restapi.tests.base import APITestCaseExtended
from restapi.utils import encrypt_with_db_secret


class StatBrowserTests(APITestCaseExtended):
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
            authkey=make_password(self.test_authkey),
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            is_superuser=True
        )


    def test_read_stats_browser(self):
        """
        Tests GET method on stats_browser
        """

        url = reverse('stats_browser')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue('other' in response.data)
        self.assertTrue('firefox' in response.data)
        self.assertTrue('chrome' in response.data)
        self.assertTrue('safari' in response.data)
        self.assertTrue('vivaldi' in response.data)


    def test_create_stats_browser(self):
        """
        Tests PUT method on stats_browser
        """

        url = reverse('stats_browser')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_update_stats_browser(self):
        """
        Tests POST method on stats_browser
        """

        url = reverse('stats_browser')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)



    def test_delete_stats_browser(self):
        """
        Tests DELETE method on stats_browser
        """

        url = reverse('stats_browser')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

