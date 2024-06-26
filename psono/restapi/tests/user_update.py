from django.urls import reverse
from django.conf import settings
from django.test.utils import override_settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.hashers import make_password
from rest_framework import status

from restapi import models

from .base import APITestCaseExtended
from ..utils import encrypt_with_db_secret, decrypt_with_db_secret, get_static_bcrypt_hash_from_email

import random
import string
import os
import json
import binascii
from mock import patch

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box
import bcrypt


class UserModificationTests(APITestCaseExtended):
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def setUp(self):

        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = bcrypt.hashpw(self.test_email.encode(), settings.EMAIL_SECRET_SALT.encode()).decode().replace(settings.EMAIL_SECRET_SALT, '', 1)
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678'
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = 'b4ce697723a93e3ba36e6da23c8728c2372069fdffc2d29c02f77cd14a106c45'
        self.test_user_obj = models.User.objects.create(
            username=self.test_username,
            email=encrypt_with_db_secret(self.test_email),
            email_bcrypt=self.test_email_bcrypt,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            hashing_algorithm="something",
            hashing_parameters={'l': 65, 'p': 2, 'r': 9, 'u': 15},
        )

        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt2 = bcrypt.hashpw(self.test_email2.encode(), settings.EMAIL_SECRET_SALT.encode()).decode().replace(settings.EMAIL_SECRET_SALT, '', 1)
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey2 = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key2 = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key2 = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key2 = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce2 = 'a67fef1ff29eb8f866feaccad336fc6311fa4c71bc183b14c8fceff7416add99'
        self.test_user_obj2 = models.User.objects.create(
            username=self.test_username2,
            email=encrypt_with_db_secret(self.test_email2),
            email_bcrypt=self.test_email_bcrypt2,
            authkey="abc",
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_get_user_update(self):
        """
        Tests GET method on user_update
        """

        url = reverse('user_update')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_delete_user_update(self):
        """
        Tests DELETE method on user_update
        """

        url = reverse('user_update')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_user_update(self):
        """
        Tests POST method on user_update
        """

        url = reverse('user_update')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def reset(self):
        url = reverse('user_update')

        data = {
            'username': self.test_username,
            'email': self.test_email,
            'email_bcrypt': self.test_email_bcrypt,
            'authkey': make_password(self.test_authkey),
            'authkey_old': self.test_public_key,
            'private_key': self.test_private_key,
            'private_key_nonce': self.test_private_key_nonce,
            'secret_key': self.test_secret_key,
            'secret_key_nonce': self.test_secret_key_nonce,
            'user_sauce': self.test_user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.client.put(url, data)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_with_private_key_not_being_in_hex_format(self):
        """
        Tests to update the user with private key not being in hex format
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = '693352a2d9af8a601e102944c19a7566e179b926450d5e00798bf3bfe1edbf00208ac3f2993db3ee3b6210cc2192ad' \
                      '39e9229f49d9bb7a0ac60d4c3c11e8ef9f05a50e9c172b2a93a267ead1b3f8121Z'
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'a67fef1ff29eb8f866feaccad336fc6311fa4c71bc183b14c8fceff7416add99'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('private_key' in response.data)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_with_language(self):
        """
        Tests to update the user with a new language
        """

        url = reverse('user_update')

        data = {
            'language': 'de',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertEqual(user.language, data['language'])

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_with_private_key_nonce_not_being_in_hex_format(self):
        """
        Tests to update the user with private key nonce not being in hex format
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = 'aa819eb039993c382449db124b5767a67738dd59e81318cZ'
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = '78caff718e1454de52a4ae09b68e969101203e2bced4f5a6ceaa2e8ece10c02c'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('private_key_nonce' in response.data)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_with_secret_key_not_being_in_hex_format(self):
        """
        Tests to update the user with private key not being in hex format
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = '693352a2d9af8a601e102944c19a7566e179b926450d5e00798bf3bfe1edbf00208ac3f2993db3ee3b6210cc2192ad' \
                      '39e9229f49d9bb7a0ac60d4c3c11e8ef9f05a50e9c172b2a93a267ead1b3f8121Z'
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'e76c0fe2a16a0bebbdcbef2b7c1d95b57d6a2c4f3f8c3c60259c3b6105c29865'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('secret_key' in response.data)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_with_secret_key_nonce_not_being_in_hex_format(self):
        """
        Tests to update the user with private key nonce not being in hex format
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = 'aa819eb039993c382449db124b5767a67738dd59e81318cZ'
        user_sauce = 'e2b048a26ba19c5ca3c923f1ec86d49f2204bbdca2f91292a045f7ad83a545f2'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('secret_key_nonce' in response.data)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user(self):
        """
        Tests to update the user
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user = models.User.objects.get(pk=self.test_user_obj.pk)


        email_bcrypt = get_static_bcrypt_hash_from_email(email)

        self.assertEqual(decrypt_with_db_secret(user.email), email)
        self.assertEqual(user.email_bcrypt, email_bcrypt)
        self.assertNotEqual(user.username, username)
        self.assertTrue(check_password(authkey, user.authkey))
        self.assertEqual(user.private_key, private_key)
        self.assertEqual(user.private_key_nonce, private_key_nonce)
        self.assertEqual(user.secret_key, secret_key)
        self.assertEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertEqual(user.user_sauce, user_sauce)
        self.assertEqual(user.hashing_algorithm, self.test_user_obj.hashing_algorithm)
        self.assertEqual(user.hashing_parameters, self.test_user_obj.hashing_parameters)

        self.reset()

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_users_hashing_algorithm_and_parameters(self):
        """
        Tests to update the user's hashing_algorithm and hashing_parameters
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
            'hashing_algorithm': 'scrypt',
            'hashing_parameters': {'l': 65, 'p': 2, 'r': 9, 'u': 15},
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertEqual(user.hashing_algorithm, data['hashing_algorithm'])
        self.assertEqual(user.hashing_parameters, data['hashing_parameters'])

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_invalid_hashing_parameters_l(self):
        """
        Tests to update the user's hashing_parameters with an invalid l
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
            'hashing_algorithm': 'scrypt',
            'hashing_parameters': {
                'l': 63,  # min 64
                'p': 2,
                'r': 9,
                'u': 15,
            },
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_invalid_hashing_parameters_p(self):
        """
        Tests to update the user's hashing_parameters with an invalid p
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
            'hashing_algorithm': 'scrypt',
            'hashing_parameters': {
                'l': 65,
                'p': 0,  # min 1
                'r': 9,
                'u': 15,
            },
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_invalid_hashing_parameters_r(self):
        """
        Tests to update the user's hashing_parameters with an invalid r
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
            'hashing_algorithm': 'scrypt',
            'hashing_parameters': {
                'l': 65,
                'p': 2,
                'r': 7,  # min 8
                'u': 15,
            },
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_invalid_hashing_parameters_u(self):
        """
        Tests to update the user's hashing_parameters with an invalid u
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
            'hashing_algorithm': 'scrypt',
            'hashing_parameters': {
                'l': 65,
                'p': 2,
                'r': 9,
                'u': 13,  # min 14
            },
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_users_hashing_algorithm_without_parameters(self):
        """
        Tests to update the user's hashing_algorithm without hashing_parameters. Either both or none of those two parameters
        need to be passed.
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
            'hashing_algorithm': 'scrypt',
            # 'hashing_parameters': {'l': 65, 'p': 2, 'r': 9, 'u': 15},
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_users_hashing_parameters_without_algorithm(self):
        """
        Tests to update the user's hashing_parameters without hashing_algorithm. Either both or none of those two parameters
        need to be passed.
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
            # 'hashing_algorithm': 'scrypt',
            'hashing_parameters': {'l': 65, 'p': 2, 'r': 9, 'u': 15},
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_without_old_password_block(self):
        """
        Tests to update the user with a new password that is the same as an old password but without the block
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.reset()

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    @patch('restapi.serializers.user_update.settings', DISABLE_LAST_PASSWORDS=1, EMAIL_SECRET_SALT=settings.EMAIL_SECRET_SALT)
    def test_update_user_with_old_password_block_1(self, mocked_fnct):
        """
        Tests to update the user with a new password that is the same as an old password
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, {'non_field_errors': ['CANNOT_REUSE_OLD_PASSWORD']})

        self.reset()

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    @patch('restapi.serializers.user_update.settings', DISABLE_LAST_PASSWORDS=2, EMAIL_SECRET_SALT=settings.EMAIL_SECRET_SALT)
    def test_update_user_with_old_password_block_2(self, mocked_fnct):
        """
        Tests to update the user with the a new password that is the same as an old password
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'cca98e49ea775ee48101df088973d0a229ff14ee0ef42f01de8c8c5fd1b36233'

        data0 = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data0)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data1 = {
            'username': username,
            'email': email,
            'authkey':  binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode(),
            'authkey_old': authkey,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data1)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data2 = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': data1['authkey'],
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data2)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, {'non_field_errors': ['CANNOT_REUSE_OLD_PASSWORD']})

        self.reset()

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_wrong_password(self):
        """
        Tests to update the user with wrong password
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = '6acc5e9cd89d5fc6b45fe4f2e6b064aa8acf1a8c7736238ada52a408f4853fe1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_with_email_duplicate(self):
        """
        Tests to update the user with an email address that already exists
        """

        url = reverse('user_update')

        email = self.test_email2
        email_bcrypt = self.test_email_bcrypt2
        username = self.test_username2
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        authkey_old = self.test_authkey
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = 'e6efde814fae7744df7490a2b55522d541ebafef562572e6565b17f79f6e0823'

        data = {
            'username': username,
            'email': email,
            'email_bcrypt': email_bcrypt,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertNotEqual(user.email, email)
        self.assertNotEqual(user.username, username)
        self.assertFalse(check_password(authkey, user.authkey))
        self.assertNotEqual(user.private_key, private_key)
        self.assertNotEqual(user.private_key_nonce, private_key_nonce)
        self.assertNotEqual(user.secret_key, secret_key)
        self.assertNotEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertNotEqual(user.user_sauce, user_sauce)

        self.reset()

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_missing_old_authkey(self):
        """
        Tests to update the user without the old authentication key
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = '12a9ef69f08060aab5fc3a2cecc851871bde511261a33241663aff74e35b8b6e'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertNotEqual(user.username, username)
        self.assertNotEqual(user.email, email)
        self.assertFalse(check_password(authkey, user.authkey))
        self.assertNotEqual(user.private_key, private_key)
        self.assertNotEqual(user.private_key_nonce, private_key_nonce)
        self.assertNotEqual(user.secret_key, secret_key)
        self.assertNotEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertNotEqual(user.user_sauce, user_sauce)

        self.reset()

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_update_user_wrong_old_authkey(self):
        """
        Tests to update the user with the wrong old authentication key
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        user_sauce = '49c9fffb9332eb75bb1862f579f9913432c88ffc4ecf7ee53ce4c7d3e9b9c861'

        data = {
            'email': email,
            'username': username,
            'authkey': authkey,
            'authkey_old': 'asdf',
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertNotEqual(user.email, email)
        self.assertNotEqual(user.username, username)
        self.assertFalse(check_password(authkey, user.authkey))
        self.assertNotEqual(user.private_key, private_key)
        self.assertNotEqual(user.private_key_nonce, private_key_nonce)
        self.assertNotEqual(user.secret_key, secret_key)
        self.assertNotEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertNotEqual(user.user_sauce, user_sauce)

        self.reset()