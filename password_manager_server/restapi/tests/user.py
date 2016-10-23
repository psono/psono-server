from django.core.urlresolvers import reverse
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from datetime import timedelta
from django.db import IntegrityError

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
        user_sauce = os.urandom(32).encode('hex')

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
        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.EMAIL_SECRET).hexdigest(), encoder=nacl.encoding.HexEncoder)

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
        user_sauce = os.urandom(32).encode('hex')

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

        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.EMAIL_SECRET).hexdigest(), encoder=nacl.encoding.HexEncoder)

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
        user_sauce = os.urandom(32).encode('hex')

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



class EmailVerificationTests(APITestCaseExtended):
    def setUp(self):

        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.EMAIL_SECRET).hexdigest(), encoder=nacl.encoding.HexEncoder)

        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = bcrypt.hashpw(self.test_email.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce = os.urandom(32).encode('hex')
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
        self.test_user_sauce = os.urandom(32).encode('hex')


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
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.assertEqual(models.Token.objects.count(), 0)


    def test_token_expiration(self):
        """
        Ensure expired tokens are invalid
        """
        url = reverse('authentication_login')

        data = {
            'username': self.test_username,
            'authkey': self.test_authkey,
            'public_key': '0146c666573f09db6466d8615dcf7bea8bdc8d232a74d1f83a22367637343306',
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data.get('token', False),
                        'Token does not exist in login response')

        token = response.data.get('token', False)

        models.Token.objects.all().update(active=True, user_validator=None)

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
        self.test_user_sauce = os.urandom(32).encode('hex')


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

        models.Token.objects.all().update(active=True, user_validator=None)

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


class UserModificationTests(APITestCaseExtended):
    def setUp(self):

        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.EMAIL_SECRET).hexdigest(), encoder=nacl.encoding.HexEncoder)

        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = bcrypt.hashpw(self.test_email.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce = os.urandom(32).encode('hex')
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
            is_email_active=True
        )

        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt2 = bcrypt.hashpw(self.test_email2.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey2 = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key2 = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key2 = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce2 = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key2 = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce2 = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce2 = os.urandom(32).encode('hex')
        self.test_user_obj2 = models.User.objects.create(
            username=self.test_username2,
            email=nacl.encoding.HexEncoder.encode(crypto_box.encrypt(self.test_email2.encode('utf-8'), nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))),
            email_bcrypt=self.test_email_bcrypt2,
            authkey=make_password(self.test_authkey2),
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

    def test_get_user_update(self):
        """
        Tests GET method on authentication_register
        """

        url = reverse('user_update')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_user_update(self):
        """
        Tests PUT method on authentication_register
        """

        url = reverse('user_update')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

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
        self.client.post(url, data)

    def test_update_user(self):
        """
        Tests to update the user
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        authkey_old = self.test_authkey
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

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
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user = models.User.objects.get(pk=self.test_user_obj.pk)


        email_bcrypt = bcrypt.hashpw(email.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)
        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.EMAIL_SECRET).hexdigest(), encoder=nacl.encoding.HexEncoder)

        self.assertEqual(crypto_box.decrypt(nacl.encoding.HexEncoder.decode(user.email)), email)
        self.assertEqual(user.email_bcrypt, email_bcrypt)
        self.assertNotEqual(user.username, username)
        self.assertTrue(check_password(authkey, user.authkey))
        self.assertEqual(user.private_key, private_key)
        self.assertEqual(user.private_key_nonce, private_key_nonce)
        self.assertEqual(user.secret_key, secret_key)
        self.assertEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertEqual(user.user_sauce, user_sauce)

        self.reset()

    def test_update_user_with_email_duplicate(self):
        """
        Tests to update the user with an email address that already exists
        """

        url = reverse('user_update')

        email = self.test_email2
        email_bcrypt = self.test_email_bcrypt2
        username = self.test_username2
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        authkey_old = self.test_authkey
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

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
        response = self.client.post(url, data)

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

    def test_update_user_missing_old_authkey(self):
        """
        Tests to update the user without the old authentication key
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

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
        response = self.client.post(url, data)

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

    def test_update_user_wrong_old_authkey(self):
        """
        Tests to update the user with the wrong old authentication key
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

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
        response = self.client.post(url, data)

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


class UserSearchTests(APITestCaseExtended):
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

        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt2 = 'b'
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey2 = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key2 = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key2 = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce2 = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key2 = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce2 = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce2 = os.urandom(32).encode('hex')
        self.test_user_obj2 = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey=make_password(self.test_authkey2),
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

    def test_get_user_search(self):
        """
        Tests GET method on user_search
        """

        url = reverse('user_search')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_user_search(self):
        """
        Tests PUT method on user_search
        """

        url = reverse('user_search')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_user_search_without_user_id_nor_user_email(self):
        """
        Tests user search without user_id nor user_email
        """

        url = reverse('user_search')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_search_with_user_id(self):
        """
        Tests users search with user_id as parameter
        """

        url = reverse('user_search')

        data = {
            'user_id': self.test_user_obj2.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertNotEqual(response.data.get('id', False), False,
                         'id (user_id) not in response')
        self.assertEqual(response.data.get('email', False), False,
                         'email in response')
        self.assertNotEqual(response.data.get('username', False), False,
                         'username not in response')
        self.assertNotEqual(response.data.get('public_key', False), False,
                         'public_key not in response')
        self.assertEqual(response.data.get('id', False), self.test_user_obj2.id,
                         'id does not match our test_user2_id')
        self.assertEqual(response.data.get('username', False), self.test_user_obj2.username,
                         'username from response does not match our username')
        self.assertEqual(response.data.get('public_key', False), self.test_user_obj2.public_key,
                         'public_key from response does not match our public_key')

    def test_user_search_with_user_email(self):
        """
        Tests users search with user_email as parameter
        """

        url = reverse('user_search')

        data = {
            'user_username': self.test_user_obj2.username,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertNotEqual(response.data.get('id', False), False,
                         'id (user_id) not in response')
        self.assertEqual(response.data.get('email', False), False,
                         'email in response')
        self.assertNotEqual(response.data.get('username', False), False,
                         'email not in response')
        self.assertNotEqual(response.data.get('public_key', False), False,
                         'public_key not in response')
        self.assertEqual(response.data.get('id', False), self.test_user_obj2.id,
                         'id does not match our test_user2_id')
        self.assertEqual(response.data.get('username', False), self.test_user_obj2.username,
                         'username from response does not match our username')
        self.assertEqual(response.data.get('public_key', False), self.test_user_obj2.public_key,
                         'public_key from response does not match our public_key')

    def test_user_search_with_bad_formatted_user_id(self):
        """
        Tests users search with bad user_id as parameter
        """

        url = reverse('user_search')

        data = {
            'user_id': '12345',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_search_with_bad_user_id(self):
        """
        Tests users search with bad user_id as parameter
        """

        url = reverse('user_search')

        data = {
            'user_id': '1747f449-5556-44a5-b6ff-e882892503e5',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_user_search_with_bad_user_email(self):
        """
        Tests users search with user_email as parameter
        """

        url = reverse('user_search')

        data = {
            'user_username': 'sexy-not-existing-email@example.com',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


