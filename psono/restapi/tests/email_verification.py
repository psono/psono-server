from django.core.urlresolvers import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from rest_framework import status

from restapi import models
from restapi.utils import generate_activation_code

from .base import APITestCaseExtended

import random
import string
import os

import nacl.encoding
import nacl.utils
import nacl.secret
import bcrypt
import hashlib
import binascii




class EmailVerificationTests(APITestCaseExtended):
    def setUp(self):

        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.DB_SECRET.encode('utf-8')).hexdigest(), encoder=nacl.encoding.HexEncoder)

        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = bcrypt.hashpw(self.test_email.encode('utf-8'), settings.EMAIL_SECRET_SALT.encode('utf-8')).decode().replace(settings.EMAIL_SECRET_SALT, '', 1)
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
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

