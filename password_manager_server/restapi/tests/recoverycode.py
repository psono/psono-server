from django.core.urlresolvers import reverse
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from datetime import timedelta
from django.db import IntegrityError
from ..authentication import TokenAuthentication

from rest_framework import status

from restapi import models
from restapi.utils import generate_activation_code

from base import APITestCaseExtended

import random
import string
import os

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box
import bcrypt
import hashlib


class RecoveryCodeTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce = os.urandom(32).encode('hex')
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

    def test_put_recoverycode(self):
        """
        Tests PUT method on recoverycode
        """

        url = reverse('recoverycode')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_get_recoverycode(self):
        """
        Tests GET method on recoverycode
        """

        url = reverse('recoverycode')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_new_recoverycode_with_empty_recovery_authkey(self):
        """
        Tests to create a new recoverycode with an empty recovery_authkey
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '',
            'recovery_data': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_authkey' in response.data)

    def test_new_recoverycode_with_no_recovery_authkey(self):
        """
        Tests to create a new recoverycode with no recovery_authkey
        """

        url = reverse('recoverycode')

        data = {
            'recovery_data': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_authkey' in response.data)

    def test_new_recoverycode_with_empty_recovery_data(self):
        """
        Tests to create a new recoverycode with an empty recovery_data
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data' in response.data)

    def test_new_recoverycode_with_no_recovery_data(self):
        """
        Tests to create a new recoverycode with no recovery_data
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data' in response.data)

    def test_new_recoverycode_with_empty_recovery_data_nonce(self):
        """
        Tests to create a new recoverycode with an empty recovery_data_nonce
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788',
            'recovery_data_nonce ': '',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data_nonce' in response.data)

    def test_new_recoverycode_with_no_recovery_data_nonce(self):
        """
        Tests to create a new recoverycode with no recovery_data_nonce
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data_nonce' in response.data)

    def test_new_recoverycode_with_empty_recovery_sauce(self):
        """
        Tests to create a new recoverycode with an empty recovery_sauce
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_sauce' in response.data)

    def test_new_recoverycode_with_no_recovery_sauce(self):
        """
        Tests to create a new recoverycode with no recovery_sauce
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788',
            'recovery_data_nonce ': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_sauce' in response.data)

    def test_new_recoverycode_without_authentication(self):
        """
        Tests to create a new recoverycode without authentication
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': 'asdf',
            'recovery_data': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_new_recoverycode(self):
        """
        Tests to create a new recoverycode
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': 'asdf',
            'recovery_data': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue('recovery_code_id' in response.data)



    def test_delete_recoverycode(self):
        """
        Tests POST method on recoverycode
        """

        url = reverse('recoverycode')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)





