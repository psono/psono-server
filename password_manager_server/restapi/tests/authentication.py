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

import logging
logging.basicConfig(level=logging.ERROR)

class RegistrationTests(APITestCaseExtended):

    def test_get_authentication_register(self):
        """
        Tests GET method on authentication_register
        """

        url = reverse('authentication_register')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_register(self):
        """
        Tests PUT method on authentication_register
        """

        url = reverse('authentication_register')

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_authentication_register(self):
        """
        Tests DELETE method on authentication_register
        """

        url = reverse('authentication_register')

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_create_account(self):
        """
        Ensure we can create a new account object.
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.User.objects.count(), 1)

        user = models.User.objects.get()

        email_bcrypt = bcrypt.hashpw(email.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)
        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.DB_SECRET).hexdigest(), encoder=nacl.encoding.HexEncoder)

        self.assertEqual(crypto_box.decrypt(nacl.encoding.HexEncoder.decode(user.email)), email)
        self.assertEqual(user.email_bcrypt, email_bcrypt)
        self.assertTrue(check_password(authkey, user.authkey))
        self.assertEqual(user.public_key, public_key)
        self.assertEqual(user.private_key, private_key)
        self.assertEqual(user.private_key_nonce, private_key_nonce)
        self.assertEqual(user.secret_key, secret_key)
        self.assertEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertEqual(user.user_sauce, user_sauce)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_email_active)

    def test_not_same_email(self):
        """
        Ensure we can not create an account with the same email address twice
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'bbd90b581b9c956e9077a8c71f61ecd9bf9355bd1aac3590bd995028ed224ae0'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.User.objects.count(), 1)

        user = models.User.objects.get()

        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.DB_SECRET).hexdigest(), encoder=nacl.encoding.HexEncoder)

        self.assertEqual(crypto_box.decrypt(nacl.encoding.HexEncoder.decode(user.email)), email)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.User.objects.count(), 1)
        self.assertTrue(response.data.get('email', False),
                        'E-Mail in error message does not exist in registration response')

    def test_no_authoritative_email(self):
        """
        Ensure we can not create an account with an authoritative email address
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = 'admin@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = '05aa27037cf893e2a4113ddbe8836e1bf395556669904902643670fbf3841338'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_account_email_no_email_syntax(self):
        """
        Test to register with a email without email syntax
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('email'), [u'Enter a valid email address.'])


    def test_create_account_username_no_email_syntax(self):
        """
        Test to register with a username without email syntax
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Enter a valid username'])


    def test_create_account_username_not_in_allowed_domains(self):
        """
        Test to register with a username that is not in allowed domains
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@nugrsiojuhsgd.com'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'The provided domain in your username is not allowed for the registration on this server.'])


    def test_create_account_username_with_not_allowed_chars(self):
        """
        Test to register with a username that contains not allowed characters
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '!@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Usernames may only contain letters, numbers, periods and dashes.'])


    def test_create_account_username_start_with_a_period(self):
        """
        Test to register with a username that starts with a period
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@' + settings.ALLOWED_DOMAINS[0]
        username = '.' + username
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Enter a valid username'])


    def test_create_account_username_start_with_a_dash(self):
        """
        Test to register with a username that starts with a dash
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@' + settings.ALLOWED_DOMAINS[0]
        username = '-' + username
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Usernames may not start with a dash.'])


    def test_create_account_username_end_with_a_period(self):
        """
        Test to register with a username that ends with a period
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '.@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Enter a valid username'])


    def test_create_account_username_not_contain_consecutive_periods(self):
        """
        Test to register with a username that contains consecutive periods
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = 'njfgdopnsrgipojr..threhtr@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Enter a valid username'])


    def test_create_account_username_not_contain_consecutive_dashes(self):
        """
        Test to register with a username that contains consecutive dashes
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = 'njfgdopnsrgipojr--threhtr@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Usernames may not contain consecutive dashes.'])


    def test_create_account_username_periods_following_dashes(self):
        """
        Test to register with a username that contains periods following dashes
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = 'njfgdopnsrgipojr-.threhtr@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Usernames may not contain dashes followed by periods.'])


    def test_create_account_username_dashes_following_periods(self):
        """
        Test to register with a username that contains dashes following periods
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = 'njfgdopnsrgipojr.-threhtr@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Usernames may not contain periods followed by dashes.'])


    def test_create_account_username_end_with_a_dash(self):
        """
        Test to register with a username that ends with a dash
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '-@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Usernames may not end with a dash.'])


    def test_create_account_username_with_only_two_chars(self):
        """
        Test to register with a username that only has 2 chars
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(2)) + '@' + settings.ALLOWED_DOMAINS[0]
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = 'd25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1'

        data = {
            'username': username,
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'Usernames may not be shorter than 3 chars.'])



class EmailVerificationTests(APITestCaseExtended):
    def setUp(self):

        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.DB_SECRET).hexdigest(), encoder=nacl.encoding.HexEncoder)

        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = bcrypt.hashpw(self.test_email.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce = '0ee09a1a2c32b240d4ac9642b218adf01c88948aa2a90f1466a8217623fc1b7e'
        self.test_user_obj = models.User.objects.create(
            username=self.test_username,
            email=nacl.encoding.HexEncoder.encode(crypto_box.encrypt(self.test_email.encode('utf-8'), nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))),
            email_bcrypt=self.test_email_bcrypt,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=False
        )

    def test_get_authentication_verify_email(self):
        """
        Tests GET method on authentication_register
        """

        url = reverse('authentication_verify_email')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_verify_email(self):
        """
        Tests PUT method on authentication_register
        """

        url = reverse('authentication_verify_email')

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_authentication_verify_email(self):
        """
        Tests DELETE method on authentication_register
        """

        url = reverse('authentication_verify_email')

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

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

        user = models.User.objects.filter(email=self.test_user_obj.email).get()

        self.assertTrue(user.is_email_active)

    def test_verify_email_wrong_code(self):
        """
        Ensure we don't verify emails with wrong codes
        """
        url = reverse('authentication_verify_email')
        activation_code = generate_activation_code(self.test_email + 'changedit')

        data = {
            'activation_code': activation_code,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = models.User.objects.filter(email=self.test_user_obj.email).get()

        self.assertFalse(user.is_email_active)


class LoginTests(APITestCaseExtended):
    def setUp(self):

        # our public / private key box
        box = PrivateKey.generate()

        self.test_email = "test@example.com"
        self.test_username = "test6@" + settings.ALLOWED_DOMAINS[0]
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = box.public_key.encode(encoder=nacl.encoding.HexEncoder)
        self.test_real_private_key = box.encode(encoder=nacl.encoding.HexEncoder)
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce = '0865977160de11fe18806e6843bc14663433982fdeadc45c217d6127f260ff33'


        data = {
            'username': self.test_username,
            'email': self.test_email,
            'authkey': self.test_authkey,
            'public_key': self.test_public_key,
            'private_key': self.test_private_key,
            'private_key_nonce': self.test_private_key_nonce,
            'secret_key': self.test_secret_key,
            'secret_key_nonce': self.test_secret_key_nonce,
            'user_sauce': self.test_user_sauce,
        }

        url = reverse('authentication_register')
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


        self.user_obj = models.User.objects.get(username=self.test_username)
        self.user_obj.is_email_active = True
        self.user_obj.save()



    def test_unique_constraint_token(self):
        key = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))

        models.Token.objects.create(
            key=key,
            user=self.user_obj
        )

        error_thrown = False

        try:
            models.Token.objects.create(
                key=key,
                user=self.user_obj
            )
        except IntegrityError:
            error_thrown = True

        self.assertTrue(error_thrown,
                        'Unique constraint lifted for Tokens which can lead to security problems')

    def test_get_authentication_login(self):
        """
        Tests GET method on authentication_register
        """

        url = reverse('authentication_login')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_authentication_login(self):
        """
        Tests DELETE method on authentication_register
        """

        url = reverse('authentication_login')

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_login(self):
        """
        Tests PUT method on authentication_register
        """

        url = reverse('authentication_login')

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_login(self):
        """
        Ensure we can login
        """
        url = reverse('authentication_login')

        data = {
            'username': self.test_username,
            'authkey': self.test_authkey,
            'public_key': 'ac3a6b1354523ff1deb48f50773005b6b7e7aea7e2639568a02c8488796dcc3f',
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data.get('token', False),
                        'Token does not exist in login response')

        self.assertEqual(response.data.get('required_multifactors', False),
                         [],
                        'required_multifactors not part of the return value or not an empty list')

        self.assertEqual(response.data.get('user', {}).get('public_key', False),
                         self.test_public_key,
                         'Public key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('private_key', False),
                         self.test_private_key,
                         'Private key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('private_key_nonce', False),
                         self.test_private_key_nonce,
                         'Private key nonce is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('user_sauce', False),
                         self.test_user_sauce,
                         'Secret key nonce is wrong in response or does not exist')

        self.assertNotEqual(response.data.get('session_public_key', False),
                         False,
                         'Session public key does not exist')
        self.assertNotEqual(response.data.get('user_validator', False),
                            False,
                            'User validator does not exist')
        self.assertNotEqual(response.data.get('user_validator_nonce', False),
                            False,
                            'User validator nonce does not exist')
        self.assertNotEqual(response.data.get('session_secret_key', False),
                         False,
                         'Session secret key does not exist')
        self.assertNotEqual(response.data.get('session_secret_key_nonce', False),
                         False,
                         'Session secret key nonce does not exist')

        self.assertEqual(models.Token.objects.count(), 1)

    def test_login_with_no_username(self):
        """
        Test to login with no username
        """
        url = reverse('authentication_login')

        data = {
            'authkey': self.test_authkey,
            'public_key': 'ac3a6b1354523ff1deb48f50773005b6b7e7aea7e2639568a02c8488796dcc3f',
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('username'), [u'This field is required.'])

    def test_login_with_no_authkey(self):
        """
        Test to login with no authkey
        """
        url = reverse('authentication_login')

        data = {
            'username': self.test_username,
            'public_key': 'ac3a6b1354523ff1deb48f50773005b6b7e7aea7e2639568a02c8488796dcc3f',
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('authkey'), [u'This field is required.'])

    def test_logi_with_google_authenticator(self):
        """
        Ensure we can login with google authenticator
        """
        url = reverse('authentication_login')

        models.Google_Authenticator.objects.create(
                user=self.user_obj,
                title= 'My TItle',
                secret = '1234'
        )

        data = {
            'username': self.test_username,
            'authkey': self.test_authkey,
            'public_key': 'ac3a6b1354523ff1deb48f50773005b6b7e7aea7e2639568a02c8488796dcc3f',
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data.get('token', False),
                        'Token does not exist in login response')

        self.assertEqual(response.data.get('required_multifactors', False),
                         ['google_authenticator_2fa'],
                        'google_authenticator_2fa not part of the required_multifactors')

        self.assertEqual(response.data.get('user', {}).get('public_key', False),
                         self.test_public_key,
                         'Public key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('private_key', False),
                         self.test_private_key,
                         'Private key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('private_key_nonce', False),
                         self.test_private_key_nonce,
                         'Private key nonce is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('user_sauce', False),
                         self.test_user_sauce,
                         'Secret key nonce is wrong in response or does not exist')

        self.assertNotEqual(response.data.get('session_public_key', False),
                         False,
                         'Session public key does not exist')
        self.assertNotEqual(response.data.get('user_validator', False),
                            False,
                            'User validator does not exist')
        self.assertNotEqual(response.data.get('user_validator_nonce', False),
                            False,
                            'User validator nonce does not exist')
        self.assertNotEqual(response.data.get('session_secret_key', False),
                         False,
                         'Session secret key does not exist')
        self.assertNotEqual(response.data.get('session_secret_key_nonce', False),
                         False,
                         'Session secret key nonce does not exist')

        self.assertEqual(models.Token.objects.count(), 1)

    def test_logi_with_yubikey_otp(self):
        """
        Ensure we can login with YubiKey OTP
        """
        url = reverse('authentication_login')

        models.Yubikey_OTP.objects.create(
                user=self.user_obj,
                title= 'My TItle',
                yubikey_id = '1234'
        )

        data = {
            'username': self.test_username,
            'authkey': self.test_authkey,
            'public_key': 'ac3a6b1354523ff1deb48f50773005b6b7e7aea7e2639568a02c8488796dcc3f',
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data.get('token', False),
                        'Token does not exist in login response')

        self.assertEqual(response.data.get('required_multifactors', False),
                         ['yubikey_otp_2fa'],
                        'yubikey_otp_2fa not part of the required_multifactors')

        self.assertEqual(response.data.get('user', {}).get('public_key', False),
                         self.test_public_key,
                         'Public key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('private_key', False),
                         self.test_private_key,
                         'Private key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('private_key_nonce', False),
                         self.test_private_key_nonce,
                         'Private key nonce is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('user_sauce', False),
                         self.test_user_sauce,
                         'Secret key nonce is wrong in response or does not exist')

        self.assertNotEqual(response.data.get('session_public_key', False),
                         False,
                         'Session public key does not exist')
        self.assertNotEqual(response.data.get('user_validator', False),
                            False,
                            'User validator does not exist')
        self.assertNotEqual(response.data.get('user_validator_nonce', False),
                            False,
                            'User validator nonce does not exist')
        self.assertNotEqual(response.data.get('session_secret_key', False),
                         False,
                         'Session secret key does not exist')
        self.assertNotEqual(response.data.get('session_secret_key_nonce', False),
                         False,
                         'Session secret key nonce does not exist')

        self.assertEqual(models.Token.objects.count(), 1)


    def test_activate_token(self):
        """
        Ensure we can activate our token
        """

        # our public / private key box
        box = PrivateKey.generate()

        # our hex encoded public / private keys
        user_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        user_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)

        url = reverse('authentication_login')

        data = {
            'username': self.test_username,
            'authkey': self.test_authkey,
            'public_key': user_session_public_key_hex,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        token = response.data.get('token', False)

        server_public_key_hex = response.data.get('session_public_key', False)

        # lets encrypt our token
        user_private_key = PrivateKey(self.test_real_private_key,
                          encoder=nacl.encoding.HexEncoder)
        user_session_private_key = PrivateKey(user_session_private_key_hex,
                          encoder=nacl.encoding.HexEncoder)
        server_public_key = PublicKey(server_public_key_hex,
                        encoder=nacl.encoding.HexEncoder)

        # create both our crypto boxes
        user_crypto_box = Box(user_private_key, server_public_key)
        session_crypto_box = Box(user_session_private_key, server_public_key)

        # decrypt session secret
        session_secret_key_nonce_hex = response.data.get('session_secret_key_nonce', False)
        session_secret_key_nonce = nacl.encoding.HexEncoder.decode(session_secret_key_nonce_hex)
        session_secret_key_hex = response.data.get('session_secret_key', False)
        session_secret_key = nacl.encoding.HexEncoder.decode(session_secret_key_hex)
        decrypted_session_key_hex = session_crypto_box.decrypt(session_secret_key, session_secret_key_nonce)

        # decrypt user validator
        user_validator_nonce_hex = response.data.get('user_validator_nonce', False)
        user_validator_nonce = nacl.encoding.HexEncoder.decode(user_validator_nonce_hex)
        user_validator_hex = response.data.get('user_validator', False)
        user_validator = nacl.encoding.HexEncoder.decode(user_validator_hex)

        decrypted_user_validator = user_crypto_box.decrypt(user_validator, user_validator_nonce)

        # encrypt user validator with session key
        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        verification_nonce_hex = nacl.encoding.HexEncoder.encode(verification_nonce)
        decrypted_session_key = nacl.encoding.HexEncoder.decode(decrypted_session_key_hex)
        secret_box = nacl.secret.SecretBox(decrypted_session_key)
        encrypted = secret_box.encrypt(decrypted_user_validator, verification_nonce)
        verification = encrypted[len(verification_nonce):]
        verification_hex = nacl.encoding.HexEncoder.encode(verification)

        url = reverse('authentication_activate_token')

        data = {
            'token': token,
            'verification': verification_hex,
            'verification_nonce': verification_nonce_hex,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data.get('user', {}).get('id', False),
                        'User ID does not exist in login response')
        self.assertEqual(response.data.get('user', {}).get('email', False),
                         self.test_email,
                         'Email is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('secret_key', False),
                         self.test_secret_key,
                         'Secret key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('secret_key_nonce', False),
                         self.test_secret_key_nonce,
                         'Secret key is wrong in response or does not exist')



    def test_login_with_wrong_password(self):
        """
        Ensure we cannot login with wrong authkey
        """
        url = reverse('authentication_login')

        data = {
            'username': self.test_username,
            'authkey': make_password(os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')),
            'public_key': 'ac3a6b1354523ff1deb48f50773005b6b7e7aea7e2639568a02c8488796dcc3f',
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'Username or password wrong.'])

        self.assertEqual(models.Token.objects.count(), 0)


    def test_token_expiration(self):
        """
        Ensure expired tokens are invalid
        """

        # lets delete all tokens
        models.Token.objects.all().delete()

        # lets create one new token
        url = reverse('authentication_login')

        data = {
            'username': self.test_username,
            'authkey': self.test_authkey,
            'public_key': '0146c666573f09db6466d8615dcf7bea8bdc8d232a74d1f83a22367637343306',
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data.get('token', False),
                        'Token does not exist in login response')

        token = response.data.get('token', False)


        # lets fake activation for our token
        tok = models.Token.objects.filter(key=TokenAuthentication.user_token_to_token_hash(token)).get()
        tok.active = True
        tok.user_validator=None
        tok.save()

        # to test we first query our datastores with the valid token

        url = reverse('datastore')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # seems to work, so lets now put the token back into the past

        token_obj = models.Token.objects.get()
        time_threshold = timezone.now() - timedelta(seconds=settings.TOKEN_TIME_VALID + 1)

        token_obj.create_date = time_threshold

        token_obj.save()

        # ... and try again

        url = reverse('datastore')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class LogoutTests(APITestCaseExtended):
    def setUp(self):

        # our public / private key box
        box = PrivateKey.generate()

        self.test_email = "test@example.com"
        self.test_username = "test6@" + settings.ALLOWED_DOMAINS[0]
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = box.public_key.encode(encoder=nacl.encoding.HexEncoder)
        self.test_real_private_key = box.encode(encoder=nacl.encoding.HexEncoder)
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce = '24350a638726c0073ec43c8c84ac110bfc2c45e7a430a257f768837f1470c9c7'


        data = {
            'username': self.test_username,
            'email': self.test_email,
            'authkey': self.test_authkey,
            'public_key': self.test_public_key,
            'private_key': self.test_private_key,
            'private_key_nonce': self.test_private_key_nonce,
            'secret_key': self.test_secret_key,
            'secret_key_nonce': self.test_secret_key_nonce,
            'user_sauce': self.test_user_sauce,
        }

        url = reverse('authentication_register')
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


        self.user_obj = models.User.objects.get(username=self.test_username)
        self.user_obj.is_email_active = True
        self.user_obj.save()

        url = reverse('authentication_login')

        data = {
            'username': self.test_username,
            'authkey': self.test_authkey,
            'public_key': '0146c666573f09db6466d8615dcf7bea8bdc8d232a74d1f83a22367637343306',
        }

        response = self.client.post(url, data)

        self.test_token = response.data.get('token', False)

        # lets fake activation for our token
        tok = models.Token.objects.filter(key=TokenAuthentication.user_token_to_token_hash(self.test_token)).get()
        tok.active = True
        tok.user_validator=None
        tok.save()

        response = self.client.post(url, data)

        self.test_token2 = response.data.get('token', False)

        # lets fake activation for our token
        tok = models.Token.objects.filter(key=TokenAuthentication.user_token_to_token_hash(self.test_token2)).get()
        tok.active = True
        tok.user_validator=None
        tok.save()

    def test_logout_false_token(self):
        """
        Try to use a fake token
        """

        url = reverse('authentication_logout')

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token + 'hackIT')
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED,
                         'Any login is accepted')


    def test_get_authentication_logout(self):
        """
        Tests GET method on authentication_register
        """

        url = reverse('authentication_logout')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_logout(self):
        """
        Tests PUT method on authentication_register
        """

        url = reverse('authentication_logout')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

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

    def test_logout_other_token(self):
        """
        Ensure we can logout other token
        """

        url = reverse('authentication_logout')


        updated_data = {
            'token': self.test_token2,
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token)
        response = self.client.post(url, updated_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK,
                         'Cannot logout with correct credentials')

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token2)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED,
                         'Logout has no real affect, Token not deleted')


class SessionTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "asd"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "abc"
        self.test_username = "test@psono.pw"
        self.test_username2 = "test2@psono.pw"
        self.test_password = "myPassword"
        self.test_authkey = "c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
                            "123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
        self.test_public_key = "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        self.test_secret_key = "a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
        self.test_secret_key_enc = "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
                                   "996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
                                   "571a48eb"
        self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce2 = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"

        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='3e7a12fcb7171c917005ef8110503ffbb85764163dbb567ef481e72a37f352a7',
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='f3c0a6788364ab164d574b655ac2a90b8124d3a20fd341c38a24566188390d01',
            is_email_active=True
        )

        self.session_secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
        self.token_u1_1 = ''.join(random.choice(string.ascii_lowercase) for _ in range(32))
        models.Token.objects.create(
            key=TokenAuthentication.user_token_to_token_hash(self.token_u1_1),
            user=self.test_user_obj,
            secret_key=self.session_secret_key,
            active=True,
            device_description='Device 1',
        )

        self.token_u1_2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(32))
        models.Token.objects.create(
            key=TokenAuthentication.user_token_to_token_hash(self.token_u1_2),
            user=self.test_user_obj,
            secret_key=self.session_secret_key,
            active=True,
            device_description='Device 2',
        )

        self.token_u2_1 = ''.join(random.choice(string.ascii_lowercase) for _ in range(32))
        models.Token.objects.create(
            key=TokenAuthentication.user_token_to_token_hash(self.token_u2_1),
            user=self.test_user2_obj,
            secret_key=self.session_secret_key,
            active=True,
            device_description='Device 3',
        )


    def test_list_datastores_without_credentials(self):
        """
        Tests if someone gets datastores without credentials
        """

        url = reverse('authentication_session')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_u1_1)
        response = self.client.get(url, data, user=self.test_user_obj)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get('sessions', False), False)

        sessions = response.data.get('sessions', [])
        self.assertEqual(len(sessions), 2)

        found_device1 = False
        found_device2 = False
        for session in response.data.get('sessions', []):
            if session['device_description'] == "Device 1":
                found_device1 = True
                self.assertEqual(session['current_session'], True)
                continue
            if session['device_description'] == "Device 2":
                found_device2 = True
                self.assertEqual(session['current_session'], False)
                continue

        self.assertTrue(found_device1)
        self.assertTrue(found_device2)






