from django.core.urlresolvers import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
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
import hashlib
import pyotp




class GoogleAuthenticatorVerifyTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '33afce78b0152075457e2a4d58b80312162f08ee932551c833b3d08d58574f03'
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

        self.token = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        self.session_secret_key = hashlib.sha256(settings.DB_SECRET.encode('utf-8')).hexdigest()
        models.Token.objects.create(
            key= hashlib.sha512(self.token.encode('utf-8')).hexdigest(),
            user=self.test_user_obj,
            secret_key=self.session_secret_key,
        )

        secret = pyotp.random_base32()
        self.totp = pyotp.TOTP(secret)

        # normally encrypt secrets, so they are not stored in plaintext with a random nonce
        secret_key = hashlib.sha256(settings.DB_SECRET.encode('utf-8')).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        encrypted_secret = crypto_box.encrypt(str(secret).encode("utf-8"), nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
        encrypted_secret_hex = nacl.encoding.HexEncoder.encode(encrypted_secret)

        models.Google_Authenticator.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            secret = encrypted_secret_hex
        )

    def test_get_authentication_ga_verify(self):
        """
        Tests GET method on authentication_ga_verify
        """

        url = reverse('authentication_ga_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_ga_verify(self):
        """
        Tests PUT method on authentication_ga_verify
        """

        url = reverse('authentication_ga_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_post_authentication_ga_verify(self):
        """
        Tests POST method on authentication_ga_verify
        """

        url = reverse('authentication_ga_verify')

        data = {
            'token': self.token,
            'ga_token': self.totp.now()
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_post_authentication_ga_verify_invalid_token(self):
        """
        Tests POST method on authentication_ga_verify with invalid token
        """

        url = reverse('authentication_ga_verify')

        data = {
            'token': '12345',
            'ga_token': self.totp.now()
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + '12345')
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_post_authentication_ga_verify_no_proper_formatted_ga_token(self):
        """
        Tests POST method on authentication_ga_verify with no proper formatted ga_token
        """

        url = reverse('authentication_ga_verify')

        data = {
            'token': self.token,
            'ga_token': 'ABCDEF'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'GA Tokens only contain digits.'])

    def test_post_authentication_ga_verify_invalid_ga_token(self):
        """
        Tests POST method on authentication_ga_verify with an invalid ga_token
        """

        url = reverse('authentication_ga_verify')

        data = {
            'token': self.token,
            'ga_token': '012345'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotEqual(response.data.get('non_field_errors', False), False)

    def test_delete_authentication_ga_verify(self):
        """
        Tests DELETE method on authentication_ga_verify
        """

        url = reverse('authentication_ga_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)



class GoogleAuthenticatorTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '6df1f310730e5464ce23e05fa4eca0de3fe30805fc8cc1d6b37389262e4bd9c3'
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

    def test_get_user_ga(self):
        """
        Tests GET method on user_ga
        """

        ga = models.Google_Authenticator.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            secret = '1234'
        )

        url = reverse('user_ga')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.data, {
            "google_authenticators":[{
                "id":ga.id,
                "title":"My Sweet Title"
            }]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_user_ga(self):
        """
        Tests PUT method on user_ga
        """

        url = reverse('user_ga')

        data = {
            'title': 'asdu5zz53',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('id', False), False)
        self.assertNotEqual(response.data.get('secret', False), False)

    def test_put_user_ga_no_title(self):
        """
        Tests PUT method on user_ga with no title
        """

        url = reverse('user_ga')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_user_ga(self):
        """
        Tests POST method on user_ga
        """

        url = reverse('user_ga')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_user_ga(self):
        """
        Tests DELETE method on user_ga
        """

        ga = models.Google_Authenticator.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            secret = '1234'
        )

        url = reverse('user_ga')

        data = {
            'google_authenticator_id': ga.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.data, {
            "google_authenticators":[]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_user_ga_no_google_authenticator_id (self):
        """
        Tests DELETE method on user_ga with no google_authenticator_id
        """

        url = reverse('user_ga')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_user_ga_google_authenticator_id_no_uuid(self):
        """
        Tests DELETE method on user_ga with google_authenticator_id not being a uuid
        """

        url = reverse('user_ga')

        data = {
            'google_authenticator_id': '12345'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('error'), 'IdNoUUID')


    def test_delete_user_ga_google_authenticator_id_not_exist(self):
        """
        Tests DELETE method on user_ga with google_authenticator_id not existing
        """

        url = reverse('user_ga')

        data = {
            'google_authenticator_id': '7e866c32-3e4d-4421-8a7d-3ac62f980fd3'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

