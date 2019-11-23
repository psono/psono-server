from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from datetime import timedelta
from rest_framework import status

from restapi import models
from ..utils import encrypt_with_db_secret

from .base import APITestCaseExtended
from mock import patch

import binascii
import random
import string
import os
import hashlib
import json

import nacl.encoding
import nacl.utils
import nacl.secret


def yubico_verify_true(yubikey_otp):
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

def yubico_verify_false(yubikey_otp):
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
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
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
        db_token = models.Token.objects.create(
            key= hashlib.sha512(self.token.encode()).hexdigest(),
            user=self.test_user_obj,
            secret_key = binascii.hexlify(os.urandom(32)).decode(),
            valid_till=timezone.now() + timedelta(seconds=10),
        )

        self.yubikey_token = 'fdnjhhfdkljhfdjhfdkljhfdjklhfdkjlhfdg'
        self.yubikey_id = self.yubikey_token[:12]

        self.yubikey = models.Yubikey_OTP.objects.create(
            user=self.test_user_obj,
            title= 'Dummy Title',
            yubikey_id = encrypt_with_db_secret(str(self.yubikey_id))
        )

        # encrypt authorization validator with session key
        secret_box = nacl.secret.SecretBox(db_token.secret_key, encoder=nacl.encoding.HexEncoder)
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        self.authorization_validator = json.dumps({
            'text': authorization_validator_hex.decode(),
            'nonce': authorization_validator_nonce_hex.decode(),
        })

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


    @patch('restapi.utils.yubikey.settings', YUBIKEY_CLIENT_ID='123', YUBIKEY_SECRET_KEY='T3VoIHlvdSBmb3VuZCBtZT8=')
    @patch('restapi.utils.yubikey.Yubico.verify', side_effect=yubico_verify_true)
    def test_post_authentication_yubikey_otp_verify_correct(self, settings_fct, yubico_verify_true_fct):
        """
        Tests POST method on authentication_yubikey_otp_verify
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {
            'token': self.token,
            'yubikey_otp': self.yubikey_token,
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    @patch('restapi.utils.yubikey.settings', YUBIKEY_CLIENT_ID=None, YUBIKEY_SECRET_KEY=None)
    def test_post_authentication_yubikey_otp_verify_no_yubikey_support(self, settings_fct):
        """
        Tests POST method on authentication_yubikey_otp_verify
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {
            'token': self.token,
            'yubikey_otp': self.yubikey_token,
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'Server does not support YubiKeys.'])


    @patch('restapi.utils.yubikey.settings', YUBIKEY_CLIENT_ID='123', YUBIKEY_SECRET_KEY='T3VoIHlvdSBmb3VuZCBtZT8=')
    @patch('restapi.utils.yubikey.Yubico.verify', side_effect=yubico_verify_false)
    def test_post_authentication_yubikey_otp_verify_yubikey_incorrect(self, settings_fct, yubico_verify_false_fct):
        """
        Tests POST method on authentication_yubikey_otp_verify while the yubikey is incorrect
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {
            'token': self.token,
            'yubikey_otp': self.yubikey_token,
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'YubiKey OTP incorrect.'])


    @patch('restapi.utils.yubikey.settings', YUBIKEY_CLIENT_ID='123', YUBIKEY_SECRET_KEY='T3VoIHlvdSBmb3VuZCBtZT8=')
    @patch('restapi.utils.yubikey.Yubico.verify', side_effect=yubico_verify_true)
    def test_post_authentication_yubikey_otp_verify_not_attached_to_this_account(self, settings_fct, yubico_verify_true_fct):
        """
        Tests POST method on authentication_yubikey_otp_verify while the yubikey_otp token is note whitelisted for the
        user that owns this token
        """

        url = reverse('authentication_yubikey_otp_verify')

        data = {
            'token': self.token,
            'yubikey_otp': '12345678',
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors'), [u'YubiKey OTP not attached to this account.'])




class YubikeyOTPTests(APITestCaseExtended):
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
                "active":yubikey.active,
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


    def test_post_user_yubikey_otp_no_parameters(self):
        """
        Tests POST method on user_yubikey_otp
        """

        url = reverse('user_yubikey_otp')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('restapi.utils.yubikey.settings', YUBIKEY_CLIENT_ID='123', YUBIKEY_SECRET_KEY='T3VoIHlvdSBmb3VuZCBtZT8=')
    @patch('restapi.utils.yubikey.Yubico.verify', side_effect=yubico_verify_true)
    def test_activate_yubikey_otp_success(self, settings_fct, yubico_verify_true_fct):
        """
        Tests POST method on user_yubikey_otp to activate a duo
        """

        yubikey_token = 'fdnjhhfdkljhfdjhfdkljhfdjklhfdkjlhfdg'
        yubikey_id = yubikey_token[:12]

        yubikey = models.Yubikey_OTP.objects.create(
            user=self.test_user_obj,
            title= 'Dummy Title',
            yubikey_id = encrypt_with_db_secret(str(yubikey_id))
        )

        url = reverse('user_yubikey_otp')

        data = {
            'yubikey_id': yubikey.id,
            'yubikey_otp': yubikey_token,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        db_yubikey = models.Yubikey_OTP.objects.get(pk=yubikey.id)
        self.assertTrue(db_yubikey.active)


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

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
