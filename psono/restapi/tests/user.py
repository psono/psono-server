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

class UserSearchTests(APITestCaseExtended):
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
        self.test_user_sauce = '7d3fcc0a89f26e0f1277d0095620a10897c03becfb2f2b27684a55b8758a0020'
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
        self.test_email_bcrypt2 = bcrypt.hashpw(self.test_email2.encode(), settings.EMAIL_SECRET_SALT.encode()).decode().replace(settings.EMAIL_SECRET_SALT, '', 1)
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'some-partial-username@psono.pw'
        self.test_authkey2 = '456'
        self.test_public_key2 = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key2 = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key2 = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce2 = '5ca7f80a0e09fe13e02102f48a88c56b2c239056b86bb2694f7923d654651ab7'
        self.test_user_obj2 = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
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

    def test_delete_user_search(self):
        """
        Tests DELETE method on user_search
        """

        url = reverse('user_search')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

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


    @patch('restapi.serializers.user_search.settings', ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL=False, ALLOW_USER_SEARCH_BY_EMAIL=True, EMAIL_SECRET_SALT=settings.EMAIL_SECRET_SALT)
    def test_user_search_with_user_username(self, mocked_settings_fnc):
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


    @patch('restapi.serializers.user_search.settings', ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL=True, ALLOW_USER_SEARCH_BY_EMAIL=True, EMAIL_SECRET_SALT=settings.EMAIL_SECRET_SALT)
    def test_user_search_with_partial_user_username(self, mocked_settings_fnc):
        """
        Tests users search with user_email as parameter
        """

        url = reverse('user_search')

        data = {
            'user_username': 'Partial', # search should be case insensitive too
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('restapi.serializers.user_search.settings', ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL=False, ALLOW_USER_SEARCH_BY_EMAIL=True, EMAIL_SECRET_SALT=settings.EMAIL_SECRET_SALT)
    def test_user_search_with_bad_user_username(self, mocked_settings_fnc):
        """
        Tests users search with user_email as parameter
        """

        url = reverse('user_search')

        data = {
            'user_username': 'sexy-not-existing-email@example.com',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('restapi.serializers.user_search.settings', ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL=True, ALLOW_USER_SEARCH_BY_EMAIL=True, EMAIL_SECRET_SALT=settings.EMAIL_SECRET_SALT)
    def test_user_search_with_bad_user_email(self, mocked_settings_fnc):
        """
        Tests users search with user_email as parameter
        """

        url = reverse('user_search')

        data = {
            'user_email': 'sexy-not-existing-email@example.com',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('restapi.serializers.user_search.settings', ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL=True, ALLOW_USER_SEARCH_BY_EMAIL=True, EMAIL_SECRET_SALT=settings.EMAIL_SECRET_SALT)
    def test_user_search_with_good_user_email(self, mocked_settings_fnc):
        """
        Tests users search with user_email as parameter
        """

        url = reverse('user_search')

        data = {
            'user_email': self.test_email2,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)




class UserActivateTokenTests(APITestCaseExtended):
    def setUp(self):
        box = PrivateKey.generate()

        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678'
        self.test_public_key = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.test_private_key = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '7a1815d667e15d6310174e4b41c22fe618e18f1748091d07c4d79eef6ec02dd2'
        self.test_user_obj = models.User.objects.create(
            email=encrypt_with_db_secret(self.test_email),
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key, # usually this one is encrypted with the user password
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

        # our public / private key box
        box = PrivateKey.generate()

        # our hex encoded public / private keys
        user_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        user_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        server_crypto_box = Box(PrivateKey(user_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                                PublicKey(settings.PUBLIC_KEY, encoder=nacl.encoding.HexEncoder))

        login_info_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = server_crypto_box.encrypt(json.dumps({
            'username': self.test_username,
            'authkey': self.test_authkey,
        }).encode("utf-8"), login_info_nonce)
        login_info_encrypted = encrypted[len(login_info_nonce):]

        data = {
            'login_info': nacl.encoding.HexEncoder.encode(login_info_encrypted).decode(),
            'login_info_nonce': nacl.encoding.HexEncoder.encode(login_info_nonce).decode(),
            'public_key': user_session_public_key_hex,
        }

        url = reverse('authentication_login')

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info')),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce'))
        ).decode())

        # Ok now lets solve the validation challenge
        # First lets decrypt our shared session secret key with the users private_session_key and the servers
        # public_session_key
        session_crypto_box = Box(PrivateKey(user_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                                 PublicKey(self.request_data.get('session_public_key'), encoder=nacl.encoding.HexEncoder))

        self.session_secret_key = session_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(self.request_data.get('session_secret_key')),
            nacl.encoding.HexEncoder.decode(self.request_data.get('session_secret_key_nonce'))
        )

        # Second step is to decrypt the user_validator with the users private key and the servers session key
        user_crypto_box = Box(PrivateKey(self.test_private_key, encoder=nacl.encoding.HexEncoder),
                                   PublicKey(self.request_data.get('session_public_key'), encoder=nacl.encoding.HexEncoder))

        self.user_validator = user_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(self.request_data.get('user_validator')),
            nacl.encoding.HexEncoder.decode(self.request_data.get('user_validator_nonce'))
        )

        # encrypt authorization validator with session key
        secret_box = nacl.secret.SecretBox(self.session_secret_key, encoder=nacl.encoding.HexEncoder)
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        self.authorization_validator = json.dumps({
            'text': authorization_validator_hex.decode(),
            'nonce': authorization_validator_nonce_hex.decode(),
        })


    def test_get_authentication_activate_token(self):
        """
        Tests GET method on authentication_activate_token
        """

        url = reverse('authentication_activate_token')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_activate_token(self):
        """
        Tests PUT method on authentication_activate_token
        """

        url = reverse('authentication_activate_token')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_post_authentication_activate_token(self):
        """
        Tests POST method on authentication_activate_token
        """

        # Third step is to encrypt the decrypted validator with the decrypted shared session secret key
        verification_crypto_box = nacl.secret.SecretBox(self.session_secret_key,
                                           encoder=nacl.encoding.HexEncoder)

        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = verification_crypto_box.encrypt(self.user_validator, verification_nonce)
        verification = encrypted[len(verification_nonce):]

        url = reverse('authentication_activate_token')

        data = {
            'token': self.request_data.get('token'),
            'verification': nacl.encoding.HexEncoder.encode(verification).decode(),
            'verification_nonce': nacl.encoding.HexEncoder.encode(verification_nonce).decode(),
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.request_data.get('token'), HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('user'), {
            'secret_key_nonce': self.test_secret_key_nonce,
            'secret_key': self.test_secret_key,
            'id': self.test_user_obj.id,
            'authentication': 'AUTHKEY',
            'email': self.test_email})

    def test_post_authentication_activate_token_token_not_already_active(self):
        """
        Tests POST method on authentication_activate_token to activate an already activated token
        """


        token_object = models.Token.objects.first()
        token_object.active=True
        token_object.save()

        # Third step is to encrypt the decrypted validator with the decrypted shared session secret key
        verification_crypto_box = nacl.secret.SecretBox(self.session_secret_key,
                                           encoder=nacl.encoding.HexEncoder)

        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = verification_crypto_box.encrypt(self.user_validator, verification_nonce)
        verification = encrypted[len(verification_nonce):]

        url = reverse('authentication_activate_token')

        data = {
            'token': self.request_data.get('token'),
            'verification': nacl.encoding.HexEncoder.encode(verification).decode(),
            'verification_nonce': nacl.encoding.HexEncoder.encode(verification_nonce).decode(),
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.request_data.get('token'), HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_authentication_activate_token_token_with_outstanding_ga_challenge(self):
        """
        Tests POST method on authentication_activate_token to activate a token that requires the google auth challenge
        to be solved first
        """


        token_object = models.Token.objects.first()
        token_object.google_authenticator_2fa=True
        token_object.save()

        # Third step is to encrypt the decrypted validator with the decrypted shared session secret key
        verification_crypto_box = nacl.secret.SecretBox(self.session_secret_key,
                                           encoder=nacl.encoding.HexEncoder)

        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = verification_crypto_box.encrypt(self.user_validator, verification_nonce)
        verification = encrypted[len(verification_nonce):]

        url = reverse('authentication_activate_token')

        data = {
            'token': self.request_data.get('token'),
            'verification': nacl.encoding.HexEncoder.encode(verification).decode(),
            'verification_nonce': nacl.encoding.HexEncoder.encode(verification_nonce).decode(),
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.request_data.get('token'), HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_authentication_activate_token_token_with_outstanding_duo_challenge(self):
        """
        Tests POST method on authentication_activate_token to activate a token that requires the duo challenge
        to be solved first
        """

        token_object = models.Token.objects.first()
        token_object.duo_2fa=True
        token_object.save()

        # Third step is to encrypt the decrypted validator with the decrypted shared session secret key
        verification_crypto_box = nacl.secret.SecretBox(self.session_secret_key,
                                           encoder=nacl.encoding.HexEncoder)

        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = verification_crypto_box.encrypt(self.user_validator, verification_nonce)
        verification = encrypted[len(verification_nonce):]

        url = reverse('authentication_activate_token')

        data = {
            'token': self.request_data.get('token'),
            'verification': nacl.encoding.HexEncoder.encode(verification).decode(),
            'verification_nonce': nacl.encoding.HexEncoder.encode(verification_nonce).decode(),
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.request_data.get('token'), HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_authentication_activate_token_token_with_outstanding_yubikey_challenge(self):
        """
        Tests POST method on authentication_activate_token to activate a token that requires the yubikey challenge
        to be solved first
        """

        token_object = models.Token.objects.first()
        token_object.yubikey_otp_2fa=True
        token_object.save()

        # Third step is to encrypt the decrypted validator with the decrypted shared session secret key
        verification_crypto_box = nacl.secret.SecretBox(self.session_secret_key,
                                           encoder=nacl.encoding.HexEncoder)

        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = verification_crypto_box.encrypt(self.user_validator, verification_nonce)
        verification = encrypted[len(verification_nonce):]

        url = reverse('authentication_activate_token')

        data = {
            'token': self.request_data.get('token'),
            'verification': nacl.encoding.HexEncoder.encode(verification).decode(),
            'verification_nonce': nacl.encoding.HexEncoder.encode(verification_nonce).decode(),
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.request_data.get('token'), HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_authentication_activate_token_incorrect_token(self):
        """
        Tests POST method on authentication_activate_token with incorrect token
        """

        # Third step is to encrypt the decrypted validator with the decrypted shared session secret key
        verification_crypto_box = nacl.secret.SecretBox(self.session_secret_key,
                                           encoder=nacl.encoding.HexEncoder)

        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = verification_crypto_box.encrypt(self.user_validator, verification_nonce)
        verification = encrypted[len(verification_nonce):]

        url = reverse('authentication_activate_token')

        data = {
            'token': 'ABC',
            'verification': nacl.encoding.HexEncoder.encode(verification).decode(),
            'verification_nonce': nacl.encoding.HexEncoder.encode(verification_nonce).decode(),
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + 'ABC', HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_post_authentication_activate_token_verification_decrypt_fail(self):
        """
        Tests POST method on authentication_activate_token with a failing verification decrypt (we test with a wrong nonce)
        """

        # Third step is to encrypt the decrypted validator with the decrypted shared session secret key
        verification_crypto_box = nacl.secret.SecretBox(self.session_secret_key,
                                           encoder=nacl.encoding.HexEncoder)

        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = verification_crypto_box.encrypt(self.user_validator, verification_nonce)
        verification = encrypted[len(verification_nonce):]

        url = reverse('authentication_activate_token')

        data = {
            'token': self.request_data.get('token'),
            'verification': nacl.encoding.HexEncoder.encode(verification).decode(),
            'verification_nonce': nacl.encoding.HexEncoder.encode('asdf'.encode("utf-8")).decode(),
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.request_data.get('token'), HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), ['VERIFICATION_CODE_INCORRECT'])

    def test_post_authentication_activate_token_wrong_user_validator(self):
        """
        Tests POST method on authentication_activate_token with a wrong user_validator
        """

        # Third step is to encrypt the decrypted validator with the decrypted shared session secret key
        verification_crypto_box = nacl.secret.SecretBox(self.session_secret_key,
                                           encoder=nacl.encoding.HexEncoder)

        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = verification_crypto_box.encrypt('asdf'.encode("utf-8"), verification_nonce)
        verification = encrypted[len(verification_nonce):]

        url = reverse('authentication_activate_token')

        data = {
            'token': self.request_data.get('token'),
            'verification': nacl.encoding.HexEncoder.encode(verification).decode(),
            'verification_nonce': nacl.encoding.HexEncoder.encode(verification_nonce).decode(),
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.request_data.get('token'), HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), ['VERIFICATION_CODE_INCORRECT'])


    def test_delete_authentication_activate_token(self):
        """
        Tests DELETE method on authentication_activate_token
        """

        url = reverse('authentication_activate_token')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)




class UserDeleteTests(APITestCaseExtended):
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
            is_email_active=True
        )

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_delete_user(self):
        """
        Tests to delete a user
        """

        url = reverse('user_delete')

        data = {
            'authkey': self.test_authkey
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_delete_user_no_authkey(self):
        """
        Tests to delete a user
        """

        url = reverse('user_delete')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_delete_user_authkey_wrong(self):
        """
        Tests to delete a user
        """

        url = reverse('user_delete')

        data = {
            'authkey': binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_delete_user_with_get(self):
        """
        Tests GET on user_delete
        """

        url = reverse('user_delete')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_delete_user_with_put(self):
        """
        Tests PUT on user_delete
        """

        url = reverse('user_delete')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def test_delete_user_with_post(self):
        """
        Tests POST on user_delete
        """

        url = reverse('user_delete')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

