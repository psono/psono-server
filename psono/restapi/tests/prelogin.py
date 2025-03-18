from django.urls import reverse
from django.conf import settings
from django.test.utils import override_settings
from rest_framework import status

from restapi import models

from .base import APITestCaseExtended

import random
import string
import binascii
import os

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey



class PreLoginTests(APITestCaseExtended):
    @override_settings(WEB_CLIENT_URL='https://psono.pw')
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
        self.user_obj.hashing_algorithm = "something"
        self.user_obj.hashing_parameters = {'l': 65, 'p': 2, 'r': 9, 'u': 15}
        self.user_obj.save()

        self.token = models.Token.objects.create(
            key=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            user=self.user_obj
        )



    def test_get_authentication_prelogin(self):
        """
        Tests GET method on authentication_prelogin
        """

        url = reverse('authentication_prelogin')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_authentication_prelogin(self):
        """
        Tests DELETE method on authentication_prelogin
        """

        url = reverse('authentication_prelogin')

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_prelogin(self):
        """
        Tests PUT method on authentication_prelogin
        """

        url = reverse('authentication_prelogin')

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_prelogin_user_exists(self):
        """
        Tests prelogin with a user that exists
        """

        data = {
            'username': self.user_obj.username,
        }

        url = reverse('authentication_prelogin')

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data.get('hashing_parameters'), {'l': 65, 'p': 2, 'r': 9, 'u': 15})
        self.assertEqual(response.data.get('hashing_algorithm'), 'something')

    def test_prelogin_user_notexists(self):
        """
        Tests prelogin with a user that doesn't exists
        """

        data = {
            'username': "i-dont-exist@example.com",
        }

        url = reverse('authentication_prelogin')

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data.get('hashing_parameters'), {'l': 64, 'p': 1, 'r': 8, 'u': 14})
        self.assertEqual(response.data.get('hashing_algorithm'), 'scrypt')



