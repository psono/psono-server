from django.core.urlresolvers import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from rest_framework import status

from restapi import models

from base import APITestCaseExtended
from mock import patch

import nacl.encoding
import nacl.utils
import nacl.secret

import random
import string
import os
import hashlib


def yubikey_authenticate_true(yubikey_otp):
    """
    utils.yubikey_authenticate function that will always return True

    :param yubikey_otp: Yubikey OTP
    :type yubikey_otp: str
    :return: True
    :rtype: Boolean
    """

    # Take exactly 1 argument which we will happily ignore afterwards
    assert yubikey_otp

    return True

def yubikey_authenticate_none(yubikey_otp):
    """
    utils.yubikey_authenticate function that will always return None

    :param yubikey_otp: Yubikey OTP
    :type yubikey_otp: str
    :return: True
    :rtype: Boolean
    """

    # Take exactly 1 argument which we will happily ignore afterwards
    assert yubikey_otp

    return None

def yubikey_authenticate_false(yubikey_otp):
    """
    utils.yubikey_authenticate function that will always return False

    :param yubikey_otp: Yubikey OTP
    :type yubikey_otp: str
    :return: True
    :rtype: Boolean
    """

    # Take exactly 1 argument which we will happily ignore afterwards
    assert yubikey_otp

    return False

class YubikeyOTPVerifyTests(APITestCaseExtended):
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
        self.test_user_sauce = 'd22f5797cfd438f212bb0830da488f0555487697ad4041bbcbf5b08bc297e117'
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
        models.Token.objects.create(
            key= hashlib.sha512(self.token).hexdigest(),
            user=self.test_user_obj
        )

        self.yubikey_token = 'fdnjhhfdkljhfdjhfdkljhfdjklhfdkjlhfdg'
        self.yubikey_id = self.yubikey_token[:12]
        # normally encrypt secrets, so they are not stored in plaintext with a random nonce
        secret_key = hashlib.sha256(settings.DB_SECRET).hexdigest()
        crypto_box = nacl.secret.SecretBox(secret_key, encoder=nacl.encoding.HexEncoder)
        encrypted_yubikey_id = crypto_box.encrypt(str(self.yubikey_id), nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE))
        encrypted_yubikey_id_hex = nacl.encoding.HexEncoder.encode(encrypted_yubikey_id)

        self.yubikey = models.Yubikey_OTP.objects.create(
            user=self.test_user_obj,
            title= 'Dummy Title',
            yubikey_id = encrypted_yubikey_id_hex
        )

    def test_get_authentication_yubikey_otp_verify(self):
        """
        Tests GET method on authentication_yubikey_otp_verify
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_yubikey_otp_verify(self):
        """
        Tests PUT method on authentication_yubikey_otp_verify
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_authentication_yubikey_otp_verify(self):
        """
        Tests DELETE method on authentication_yubikey_otp_verify
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    @patch('restapi.serializers.yubikey_otp_verify.yubikey_authenticate', side_effect=yubikey_authenticate_true)
    def test_post_authentication_yubikey_otp_verify_correct(self, yubikey_authenticate_fct):
        """
        Tests POST method on authentication_yubikey_otp_verify
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {
            'token': self.token,
            'yubikey_otp': self.yubikey_token,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    @patch('restapi.serializers.yubikey_otp_verify.yubikey_authenticate', side_effect=yubikey_authenticate_none)
    def test_post_authentication_yubikey_otp_verify_no_yubikey_support(self, yubikey_authenticate_fct):
        """
        Tests POST method on authentication_yubikey_otp_verify
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {
            'token': self.token,
            'yubikey_otp': self.yubikey_token,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'Server does not support YubiKeys.'])


    @patch('restapi.serializers.yubikey_otp_verify.yubikey_authenticate', side_effect=yubikey_authenticate_false)
    def test_post_authentication_yubikey_otp_verify_yubikey_incorrect(self, yubikey_authenticate_fct):
        """
        Tests POST method on authentication_yubikey_otp_verify while the yubikey is incorrect
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {
            'token': self.token,
            'yubikey_otp': self.yubikey_token,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'YubiKey OTP incorrect.'])


    @patch('restapi.serializers.yubikey_otp_verify.yubikey_authenticate', side_effect=yubikey_authenticate_true)
    def test_post_authentication_yubikey_otp_verify_token_incorrect(self, yubikey_authenticate_fct):
        """
        Tests POST method on authentication_yubikey_otp_verify with an incorrect token
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {
            'token': '12345678',
            'yubikey_otp': self.yubikey_token,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'Token incorrect.'])


    @patch('restapi.serializers.yubikey_otp_verify.yubikey_authenticate', side_effect=yubikey_authenticate_true)
    def test_post_authentication_yubikey_otp_verify_not_attached_to_this_account(self, yubikey_authenticate_fct):
        """
        Tests POST method on authentication_yubikey_otp_verify while the yubikey_otp token is note whitelisted for the
        user that owns this token
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {
            'token': self.token,
            'yubikey_otp': '12345678',
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'YubiKey OTP not attached to this account.'])




class YubikeyOTPTests(APITestCaseExtended):
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
        self.test_user_sauce = '32a34bd9d7ae7fde45906bce0e7b04c3f81e4b6c05d888468e717e173ee6655a'
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

    def test_get_user_yubikey_otp(self):
        """
        Tests GET method on yubikey_otp
        """

        yubikey = models.Yubikey_OTP.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            yubikey_id = '1234'
        )

        url = reverse('user_yubikey_otp')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.data, {
            "yubikey_otps":[{
                "id":yubikey.id,
                "title":"My Sweet Title"
            }]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_user_yubikey_otp_with_no_valid_yubikey(self):
        """
        Tests PUT method on user_yubikey_otp with no valid yubikey
        """

        url = reverse('user_yubikey_otp')

        data = {
            'title': 'asdu5zz53',
            'yubikey_otp': '123456789',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotEqual(response.data.get('yubikey_otp', False), False)

    def test_put_user_yubikey_otp_no_yubikey_otp(self):
        """
        Tests PUT method on user_yubikey_otp with no yubikey_otp
        """

        url = reverse('user_yubikey_otp')

        data = {
            'title': 'asdu5zz53',
        }


        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_put_user_yubikey_otp_no_title(self):
        """
        Tests PUT method on user_yubikey_otp with no title
        """

        url = reverse('user_yubikey_otp')

        data = {
            'yubikey_otp': '123456789',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_post_user_yubikey_otp(self):
        """
        Tests POST method on user_yubikey_otp
        """

        url = reverse('user_yubikey_otp')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_user_yubikey_otp(self):
        """
        Tests DELETE method on user_yubikey_otp
        """

        yubikey = models.Yubikey_OTP.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            yubikey_id = '1234'
        )

        url = reverse('user_yubikey_otp')

        data = {
            'yubikey_otp_id': yubikey.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.data, {
            "yubikey_otps":[]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_user_yubikey_otp_no_yubikey_otp_id (self):
        """
        Tests DELETE method on user_yubikey_otp with no google_authenticator_id
        """

        url = reverse('user_yubikey_otp')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_user_yubikey_otp_yubikey_otp_id_no_uuid(self):
        """
        Tests DELETE method on user_yubikey_otp with yubikey_otp_id not being a uuid
        """

        url = reverse('user_yubikey_otp')

        data = {
            'yubikey_otp_id': '12345'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('error'), 'IdNoUUID')


    def test_delete_user_yubikey_otp_yubikey_otp_id_not_exist(self):
        """
        Tests DELETE method on user_yubikey_otp with yubikey_otp_id not existing
        """

        url = reverse('user_yubikey_otp')

        data = {
            'yubikey_otp_id': '7e866c32-3e4d-4421-8a7d-3ac62f980fd3'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
