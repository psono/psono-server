from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from rest_framework import status

import pyotp
import random
import string
import binascii
import os

from restapi import models
from restapi.tests.base import APITestCaseExtended
from restapi.utils import encrypt_with_db_secret


class DeleteGATests(APITestCaseExtended):
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

        secret = pyotp.random_base32()
        self.totp = pyotp.TOTP(secret)

        self.ga = models.Google_Authenticator.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            secret = encrypt_with_db_secret(str(secret))
        )


    def test_delete_ga_success(self):
        """
        Tests DELETE method on ga
        """

        url = reverse('admin_google_authenticator')

        data = {
            'google_authenticator_id': self.ga.id
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.Google_Authenticator.objects.all().count(), 0)


    def test_delete_ga_failure_no_admin(self):
        """
        Tests DELETE method on ga without being an admin
        """

        url = reverse('admin_google_authenticator')

        data = {
            'google_authenticator_id': self.ga.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_delete_ga_failure_no_ga_id(self):
        """
        Tests DELETE method on ga without a ga id
        """

        url = reverse('admin_google_authenticator')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_ga_failure_ga_id_not_exist(self):
        """
        Tests DELETE method on ga with a ga id that does not exist
        """

        url = reverse('admin_google_authenticator')

        data = {
            'google_authenticator_id': '499d3c84-e8ae-4a6b-a4c2-43c79beb069a'
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

