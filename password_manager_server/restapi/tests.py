from django.core.urlresolvers import reverse
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password

from rest_framework import status
from rest_framework.test import APITestCase, APIClient

import models
from utils import generate_activation_code

import random
import string
import os


class RegistrationTests(APITestCase):
    def test_create_account(self):
        """
        Ensure we can create a new account object.
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))+ '@sachapfeiffer.com'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')

        data = {
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.Data_Store_Owner.objects.count(), 1)

        owner = models.Data_Store_Owner.objects.get()

        self.assertEqual(owner.email, email)
        self.assertTrue(check_password(authkey, owner.authkey))
        self.assertEqual(owner.public_key, public_key)
        self.assertEqual(owner.private_key, private_key)
        self.assertEqual(owner.private_key_nonce, private_key_nonce)
        self.assertEqual(owner.secret_key, secret_key)
        self.assertEqual(owner.secret_key_nonce, secret_key_nonce)
        self.assertTrue(owner.is_active)
        self.assertFalse(owner.is_email_active)


class EmailVerificationTests(APITestCase):

    def setUp(self):
        self.test_email = u"test@test.de"
        models.Data_Store_Owner.objects.create(email=self.test_email)

    def test_verify_email(self):
        """
        Ensure we can verify the email
        """
        url = reverse('authentication_verify_email')
        activation_code = generate_activation_code(self.test_email)

        data = {
            'activation_code': activation_code,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        owner = models.Data_Store_Owner.objects.filter(email=self.test_email).get()

        self.assertTrue(owner.is_email_active)

class LoginTests(APITestCase):

    def setUp(self):
        self.test_email = u"test@test.de"
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        models.Data_Store_Owner.objects.create(
            email=self.test_email,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            is_email_active=True
        )

    def test_login(self):
        """
        Ensure we can login
        """
        url = reverse('authentication_login')

        data = {
            'email': self.test_email,
            'authkey': self.test_authkey,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data.get('token', False),
                        'Token does not exist in login response')
        self.assertTrue(response.data.get('datastore_owner', {}).get('id', False),
                        'User ID does not exist in login response')
        self.assertEqual(response.data.get('datastore_owner', {}).get('public_key', False),
                         self.test_public_key,
                        'Public key is wrong in response or does not exist')
        self.assertEqual(response.data.get('datastore_owner', {}).get('private_key', False),
                         self.test_private_key,
                        'Private key is wrong in response or does not exist')
        self.assertEqual(response.data.get('datastore_owner', {}).get('private_key_nonce', False),
                         self.test_private_key_nonce,
                        'Private key nonce is wrong in response or does not exist')
        self.assertEqual(response.data.get('datastore_owner', {}).get('secret_key', False),
                         self.test_secret_key,
                        'Secret key is wrong in response or does not exist')
        self.assertEqual(response.data.get('datastore_owner', {}).get('secret_key_nonce', False),
                         self.test_secret_key_nonce,
                        'Secret key nonce is wrong in response or does not exist')

        self.assertEqual(models.Token.objects.count(), 1)

class LogoutTests(APITestCase):

    def setUp(self):
        self.test_email = u"test@test.de"
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        models.Data_Store_Owner.objects.create(
            email=self.test_email,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            is_email_active=True
        )

        url = reverse('authentication_login')

        data = {
            'email': self.test_email,
            'authkey': self.test_authkey,
        }

        response = self.client.post(url, data)

        self.test_token = response.data.get('token', False)

    def test_logout_false_token(self):
        """
        Try to use a fake token
        """

        url = reverse('authentication_logout')


        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token + 'hackIT')
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED,
                         'Any login is accepted')


    def test_logout(self):
        """
        Ensure we can logout
        """

        url = reverse('authentication_logout')


        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK,
                         'Cannot logout with correct credentials')


        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED,
                         'Logout has no real affect, Token not deleted')