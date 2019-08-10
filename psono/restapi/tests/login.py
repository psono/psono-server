from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from datetime import timedelta
from django.db import IntegrityError
from ..authentication import TokenAuthentication
from rest_framework import status

from restapi import models

from .base import APITestCaseExtended
from ..utils import encrypt_with_db_secret

import json
import random
import string
import binascii
import os

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box



class LoginTests(APITestCaseExtended):
    def setUp(self):

        # our public / private key box
        box = PrivateKey.generate()

        self.test_email = "test@example.com"
        self.test_username = "test6@" + settings.ALLOWED_DOMAINS[0]
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.test_real_private_key = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
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

        self.token = models.Token.objects.create(
            key=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            user=self.user_obj
        )


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

        request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info')),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce'))
        ).decode())

        self.assertTrue(request_data.get('token', False),
                        'Token does not exist in login response')

        self.assertEqual(request_data.get('required_multifactors', False),
                         [],
                        'required_multifactors not part of the return value or not an empty list')

        self.assertEqual(request_data.get('user', {}).get('public_key', False),
                         self.test_public_key,
                         'Public key is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('private_key', False),
                         self.test_private_key,
                         'Private key is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('private_key_nonce', False),
                         self.test_private_key_nonce,
                         'Private key nonce is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('user_sauce', False),
                         self.test_user_sauce,
                         'Secret key nonce is wrong in response or does not exist')

        self.assertNotEqual(request_data.get('session_public_key', False),
                         False,
                         'Session public key does not exist')
        self.assertNotEqual(request_data.get('user_validator', False),
                            False,
                            'User validator does not exist')
        self.assertNotEqual(request_data.get('user_validator_nonce', False),
                            False,
                            'User validator nonce does not exist')
        self.assertNotEqual(request_data.get('session_secret_key', False),
                         False,
                         'Session secret key does not exist')
        self.assertNotEqual(request_data.get('session_secret_key_nonce', False),
                         False,
                         'Session secret key nonce does not exist')

        self.assertEqual(models.Token.objects.count(), 1)

    def test_login_with_corrupted_login_info(self):
        """
        Try to login with corrupted login info
        """

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
            'login_info': nacl.encoding.HexEncoder.encode(login_info_encrypted).decode() + 'corrupted',
            'login_info_nonce': nacl.encoding.HexEncoder.encode(login_info_nonce).decode(),
            'public_key': user_session_public_key_hex,
        }

        url = reverse('authentication_login')

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['non_field_errors'], ['Login info cannot be decrypted'])

    def test_login_with_disabled_user(self):
        """
        Try to login with a disabled user
        """

        self.user_obj.is_active = False
        self.user_obj.save()

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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_with_user_where_email_is_not_verified(self):
        """
        Try to login with a user who did not yet verify his email address
        """

        self.user_obj.is_email_active = False
        self.user_obj.save()

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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_login_failure_no_login_info(self):
        """
        Test to login without login info
        """

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
            # 'login_info': nacl.encoding.HexEncoder.encode(login_info_encrypted).decode(),
            'login_info_nonce': nacl.encoding.HexEncoder.encode(login_info_nonce).decode(),
            'public_key': user_session_public_key_hex,
        }

        url = reverse('authentication_login')

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_failure_no_login_info_nonce(self):
        """
        Test to login without login info nonce
        """

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
            # 'login_info_nonce': nacl.encoding.HexEncoder.encode(login_info_nonce).decode(),
            'public_key': user_session_public_key_hex,
        }

        url = reverse('authentication_login')

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_failure_no_public_key(self):
        """
        Test to login without public_key
        """

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
            # 'public_key': user_session_public_key_hex,
        }

        url = reverse('authentication_login')

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_with_no_username(self):
        """
        Test to login with no username
        """
        """
        Ensure we can login
        """

        # our public / private key box
        box = PrivateKey.generate()

        # our hex encoded public / private keys
        user_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        user_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        server_crypto_box = Box(PrivateKey(user_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                                PublicKey(settings.PUBLIC_KEY, encoder=nacl.encoding.HexEncoder))

        login_info_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = server_crypto_box.encrypt(json.dumps({
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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.assertEqual(response.data.get('non_field_errors'), [u'No username specified.'])

    def test_login_with_no_authkey(self):
        """
        Test to login with no authkey
        """
        """
        Ensure we can login
        """

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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.assertEqual(response.data.get('non_field_errors'), [u'No authkey specified.'])

    def test_login_with_google_authenticator(self):
        """
        Ensure we can login with google authenticator
        """
        url = reverse('authentication_login')

        models.Google_Authenticator.objects.create(
                user=self.user_obj,
                title= 'My TItle',
                secret = '1234'
        )

        self.user_obj.google_authenticator_enabled = True
        self.user_obj.save()

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

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info')),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce'))
        ).decode())


        self.assertTrue(request_data.get('token', False),
                        'Token does not exist in login response')

        self.assertEqual(request_data.get('required_multifactors', False),
                         ['google_authenticator_2fa'],
                        'google_authenticator_2fa not part of the required_multifactors')

        self.assertEqual(request_data.get('user', {}).get('public_key', False),
                         self.test_public_key,
                         'Public key is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('private_key', False),
                         self.test_private_key,
                         'Private key is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('private_key_nonce', False),
                         self.test_private_key_nonce,
                         'Private key nonce is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('user_sauce', False),
                         self.test_user_sauce,
                         'Secret key nonce is wrong in response or does not exist')

        self.assertNotEqual(request_data.get('session_public_key', False),
                         False,
                         'Session public key does not exist')
        self.assertNotEqual(request_data.get('user_validator', False),
                            False,
                            'User validator does not exist')
        self.assertNotEqual(request_data.get('user_validator_nonce', False),
                            False,
                            'User validator nonce does not exist')
        self.assertNotEqual(request_data.get('session_secret_key', False),
                         False,
                         'Session secret key does not exist')
        self.assertNotEqual(request_data.get('session_secret_key_nonce', False),
                         False,
                         'Session secret key nonce does not exist')

        self.assertEqual(models.Token.objects.count(), 1)

    def test_login_with_yubikey_otp(self):
        """
        Ensure we can login with YubiKey OTP
        """
        url = reverse('authentication_login')

        models.Yubikey_OTP.objects.create(
                user=self.user_obj,
                title= 'My TItle',
                yubikey_id = '1234'
        )

        self.user_obj.yubikey_otp_enabled = True
        self.user_obj.save()

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

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info')),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce'))
        ).decode())

        self.assertTrue(request_data.get('token', False),
                        'Token does not exist in login response')

        self.assertEqual(request_data.get('required_multifactors', False),
                         ['yubikey_otp_2fa'],
                        'yubikey_otp_2fa not part of the required_multifactors')

        self.assertEqual(request_data.get('user', {}).get('public_key', False),
                         self.test_public_key,
                         'Public key is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('private_key', False),
                         self.test_private_key,
                         'Private key is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('private_key_nonce', False),
                         self.test_private_key_nonce,
                         'Private key nonce is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('user_sauce', False),
                         self.test_user_sauce,
                         'Secret key nonce is wrong in response or does not exist')

        self.assertNotEqual(request_data.get('session_public_key', False),
                         False,
                         'Session public key does not exist')
        self.assertNotEqual(request_data.get('user_validator', False),
                            False,
                            'User validator does not exist')
        self.assertNotEqual(request_data.get('user_validator_nonce', False),
                            False,
                            'User validator nonce does not exist')
        self.assertNotEqual(request_data.get('session_secret_key', False),
                         False,
                         'Session secret key does not exist')
        self.assertNotEqual(request_data.get('session_secret_key_nonce', False),
                         False,
                         'Session secret key nonce does not exist')

        self.assertEqual(models.Token.objects.count(), 1)

    def test_login_with_duo(self):
        """
        Ensure we can login with duo
        """
        url = reverse('authentication_login')

        models.Duo.objects.create(
            user=self.user_obj,
            title= 'My Sweet Title',
            duo_integration_key = 'duo_integration_key',
            duo_secret_key = encrypt_with_db_secret('duo_secret_key'),
            duo_host = 'duo_secret_key',
            enrollment_user_id = 'enrollment_user_id',
            enrollment_activation_code = 'enrollment_activation_code',
            enrollment_expiration_date = timezone.now() + timedelta(seconds=600),
            active = True,
        )

        self.user_obj.duo_enabled = True
        self.user_obj.save()

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

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info')),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce'))
        ).decode())

        self.assertTrue(request_data.get('token', False),
                        'Token does not exist in login response')

        self.assertEqual(request_data.get('required_multifactors', False),
                         ['duo_2fa'],
                        'duo_2fa not part of the required_multifactors')

        self.assertEqual(request_data.get('user', {}).get('public_key', False),
                         self.test_public_key,
                         'Public key is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('private_key', False),
                         self.test_private_key,
                         'Private key is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('private_key_nonce', False),
                         self.test_private_key_nonce,
                         'Private key nonce is wrong in response or does not exist')
        self.assertEqual(request_data.get('user', {}).get('user_sauce', False),
                         self.test_user_sauce,
                         'Secret key nonce is wrong in response or does not exist')

        self.assertNotEqual(request_data.get('session_public_key', False),
                         False,
                         'Session public key does not exist')
        self.assertNotEqual(request_data.get('user_validator', False),
                            False,
                            'User validator does not exist')
        self.assertNotEqual(request_data.get('user_validator_nonce', False),
                            False,
                            'User validator nonce does not exist')
        self.assertNotEqual(request_data.get('session_secret_key', False),
                         False,
                         'Session secret key does not exist')
        self.assertNotEqual(request_data.get('session_secret_key_nonce', False),
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
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info').decode()),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce').decode())
        ).decode())

        token = request_data.get('token', False)

        server_public_key_hex = request_data.get('session_public_key', False)

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
        session_secret_key_nonce_hex = request_data.get('session_secret_key_nonce', False)
        session_secret_key_nonce = nacl.encoding.HexEncoder.decode(session_secret_key_nonce_hex)
        session_secret_key_hex = request_data.get('session_secret_key', False)
        session_secret_key = nacl.encoding.HexEncoder.decode(session_secret_key_hex)
        decrypted_session_key_hex = session_crypto_box.decrypt(session_secret_key, session_secret_key_nonce)

        # decrypt user validator
        user_validator_nonce_hex = request_data.get('user_validator_nonce', False)
        user_validator_nonce = nacl.encoding.HexEncoder.decode(user_validator_nonce_hex)
        user_validator_hex = request_data.get('user_validator', False)
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

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': token,
            'verification': verification_hex.decode(),
            'verification_nonce': verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + token,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
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
            'authkey': make_password(binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()),
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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'USERNAME_OR_PASSWORD_WRONG'])

        self.assertEqual(models.Token.objects.count(), 0)


    def test_token_expiration(self):
        """
        Ensure expired tokens are invalid
        """

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

        # lets delete all tokens
        models.Token.objects.all().delete()

        # lets create one new token
        url = reverse('authentication_login')

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info')),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce'))
        ).decode())

        self.assertTrue(request_data.get('token', False),
                        'Token does not exist in login response')

        token = request_data.get('token', False)


        # lets fake activation for our token
        tok = models.Token.objects.filter(key=TokenAuthentication.user_token_to_token_hash(token)).get()
        tok.active = True
        tok.user_validator=None
        tok.save()


        # encrypt authorization validator with session key
        secret_box = nacl.secret.SecretBox(tok.secret_key, encoder=nacl.encoding.HexEncoder)
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        # to test we first query our datastores with the valid token

        url = reverse('datastore')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            }))
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # seems to work, so lets now put the token back into the past

        token_obj = models.Token.objects.get()

        token_obj.valid_till = timezone.now() - timedelta(seconds=10)

        token_obj.save()

        # ... and try again

        url = reverse('datastore')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            }))
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)








