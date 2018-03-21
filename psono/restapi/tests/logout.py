from django.urls import reverse
from django.conf import settings
from ..authentication import TokenAuthentication
from rest_framework import status

from restapi import models

from .base import APITestCaseExtended

import os
import json
import binascii

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box

class LogoutTests(APITestCaseExtended):
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

        response = self.client.post(url, data)

        request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info')),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce'))
        ).decode())

        self.test_token = request_data.get('token', False)

        # lets fake activation for our token
        tok = models.Token.objects.filter(key=TokenAuthentication.user_token_to_token_hash(self.test_token)).get()
        tok.active = True
        tok.user_validator=None
        tok.save()

        response = self.client.post(url, data)

        request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info')),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce'))
        ).decode())

        self.test_token2 = request_data.get('token', False)

        # lets fake activation for our token
        self.tok2 = models.Token.objects.filter(key=TokenAuthentication.user_token_to_token_hash(self.test_token2)).get()
        self.tok2.active = True
        self.tok2.user_validator=None
        self.tok2.save()

        # encrypt authorization validator with session key
        secret_box = nacl.secret.SecretBox(tok.secret_key, encoder=nacl.encoding.HexEncoder)
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        self.authorization_validator1 = json.dumps({
            'text': authorization_validator_hex.decode(),
            'nonce': authorization_validator_nonce_hex.decode(),
        })

        # encrypt authorization validator with session key
        secret_box = nacl.secret.SecretBox(self.tok2.secret_key, encoder=nacl.encoding.HexEncoder)
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        self.authorization_validator2 = json.dumps({
            'text': authorization_validator_hex.decode(),
            'nonce': authorization_validator_nonce_hex.decode(),
        })

    def test_logout_false_token(self):
        """
        Try to use a fake token
        """

        url = reverse('authentication_logout')

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token + 'hackIT', HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator1)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED,
                         'Any login is accepted')


    def test_get_authentication_logout(self):
        """
        Tests GET method on authentication_register
        """

        url = reverse('authentication_logout')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator1)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_logout(self):
        """
        Tests PUT method on authentication_register
        """

        url = reverse('authentication_logout')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator1)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_authentication_logout(self):
        """
        Tests DELETE method on authentication_register
        """

        url = reverse('authentication_logout')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator1)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_logout(self):
        """
        Ensure we can logout
        """

        url = reverse('authentication_logout')

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator1)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK,
                         'Cannot logout with correct credentials')

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator1)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED,
                         'Logout has no real affect, Token not deleted')

    def test_logout_other_token(self):
        """
        Ensure we can logout other token
        """

        url = reverse('authentication_logout')


        updated_data = {
            'session_id': self.tok2.id,
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator1)
        response = self.client.post(url, updated_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK,
                         'Cannot logout with correct credentials')

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token2, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator2)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED,
                         'Logout has no real affect, Token not deleted')

    def test_logout_other_token_that_does_not_exist(self):
        """
        Ensure we can logout other token
        """

        url = reverse('authentication_logout')


        updated_data = {
            'session_id': '5ae48987-29c2-4c07-b50e-4ee35556d63e'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator1)
        response = self.client.post(url, updated_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


