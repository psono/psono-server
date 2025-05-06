from django.urls import reverse
from django.conf import settings
from django.test.utils import override_settings
from rest_framework import status

from restapi import models
from .base import APITestCaseExtended
from ..utils import encrypt_with_db_secret
from ..utils import generate_unregistration_code

import bcrypt
import binascii
import random
import string
import os


class UnegistrationTests(APITestCaseExtended):

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
        self.test_user_sauce = '0ee09a1a2c32b240d4ac9642b218adf01c88948aa2a90f1466a8217623fc1b7e'
        self.test_user_obj = models.User.objects.create(
            username=self.test_username,
            email=encrypt_with_db_secret(self.test_email),
            email_bcrypt=self.test_email_bcrypt,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=False
        )

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_get_authentication_unregister(self):
        """
        Tests GET method on authentication_unregister
        """

        url = reverse('authentication_unregister')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_delete_authentication_unregister(self):
        """
        Tests DELETE method on authentication_unregister
        """

        url = reverse('authentication_unregister')

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_authentication_unregister_username(self):
        """
        Tests POST method on authentication_unregister with username
        """

        url = reverse('authentication_unregister')

        data = {
            'username': self.test_username
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_authentication_unregister_invalid_username(self):
        """
        Tests POST method on authentication_unregister with invalid username
        """

        url = reverse('authentication_unregister')

        data = {
            'username': "invalid@example.com"
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), ['USER_WITH_USERNAME_DOESNT_EXIST'])

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_authentication_unregister_email(self):
        """
        Tests POST method on authentication_unregister with email
        """

        url = reverse('authentication_unregister')

        data = {
            'email': self.test_email
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    @override_settings(WEB_CLIENT_URL='')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_authentication_unregister_missing_webclient_url(self):
        """
        Tests POST method on authentication_unregister yet without configuring a WEB_CLIENT_URL
        """

        url = reverse('authentication_unregister')

        data = {
            'email': self.test_email
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_authentication_unregister_invalid_email(self):
        """
        Tests POST method on authentication_unregister with invalid email
        """

        url = reverse('authentication_unregister')

        data = {
            'email': 'invalid@example.com'
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), ['USER_WITH_EMAIL_DOESNT_EXIST'])

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_authentication_unregister_email_and_username(self):
        """
        Tests POST method on authentication_unregister with an email and username
        """

        url = reverse('authentication_unregister')

        data = {
            'username': 'invalid@example.com',
            'email': 'invalid@example.com',
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), ['EITHER_USERNAME_OR_EMAIL_NEED_TO_BE_DEFINED_NOT_BOTH'])

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_post_authentication_unregister_without_email_and_username(self):
        """
        Tests POST method on authentication_unregister without an email and username
        """

        url = reverse('authentication_unregister')

        data = {
            # 'username': 'invalid@example.com',
            # 'email': 'invalid@example.com',
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), ['EITHER_USERNAME_OR_EMAIL_NEED_TO_BE_DEFINED'])

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_authentication_unregister_email_unverified(self):
        """
        Tests PUT method on authentication_unregister with user who has not yet verified his email address
        """
        self.test_user_obj.is_email_active = False
        self.test_user_obj.save()

        url = reverse('authentication_unregister')
        unregister_code = generate_unregistration_code(self.test_email)

        data = {
            'unregister_code': unregister_code,
        }

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertFalse(models.User.objects.filter(pk=self.test_user_obj.pk).exists())

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_authentication_unregister_email_verified(self):
        """
        Tests PUT method on authentication_unregister with user who has already verified his email address
        """
        self.test_user_obj.is_email_active = True
        self.test_user_obj.save()

        url = reverse('authentication_unregister')
        unregister_code = generate_unregistration_code(self.test_email)

        data = {
            'unregister_code': unregister_code,
        }

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertFalse(models.User.objects.filter(pk=self.test_user_obj.pk).exists())

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_put_authentication_unregister_invalid_unregistration_code(self):
        """
        Tests PUT method on authentication_unregister with an invalid unregistration code
        """
        self.assertTrue(models.User.objects.filter(pk=self.test_user_obj.pk).exists())

        url = reverse('authentication_unregister')

        data = {
            'unregister_code': 'abc',
        }

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), ['UNREGISTRATION_CODE_INCORRECT'])

        self.assertTrue(models.User.objects.filter(pk=self.test_user_obj.pk).exists())