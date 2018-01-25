from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone

from rest_framework import status

from restapi import models

from .base import APITestCaseExtended

from ..utils import readbuffer
import random
import string
import os
import datetime
import json
import binascii

import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box


class RecoveryCodeTests(APITestCaseExtended):
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
        self.test_user_sauce = 'ef37b3192178b9a97b551572314388058c14a4dabdbf63d022bcba9951809b6d'
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

    def test_put_recoverycode(self):
        """
        Tests PUT method on recoverycode
        """

        url = reverse('recoverycode')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_get_recoverycode(self):
        """
        Tests GET method on recoverycode
        """

        url = reverse('recoverycode')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_new_recoverycode_with_empty_recovery_authkey(self):
        """
        Tests to create a new recoverycode with an empty recovery_authkey
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '',
            'recovery_data': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_authkey' in response.data)

    def test_new_recoverycode_with_no_recovery_authkey(self):
        """
        Tests to create a new recoverycode with no recovery_authkey
        """

        url = reverse('recoverycode')

        data = {
            'recovery_data': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_authkey' in response.data)

    def test_new_recoverycode_with_empty_recovery_data(self):
        """
        Tests to create a new recoverycode with an empty recovery_data
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data' in response.data)

    def test_new_recoverycode_with_no_recovery_data(self):
        """
        Tests to create a new recoverycode with no recovery_data
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data' in response.data)

    def test_new_recoverycode_with_recovery_data_not_in_hex(self):
        """
        Tests to create a new recoverycode with recovery_data not in hex
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788X',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data' in response.data)

    def test_new_recoverycode_with_empty_recovery_data_nonce(self):
        """
        Tests to create a new recoverycode with an empty recovery_data_nonce
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788',
            'recovery_data_nonce ': '',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data_nonce' in response.data)

    def test_new_recoverycode_with_no_recovery_data_nonce(self):
        """
        Tests to create a new recoverycode with no recovery_data_nonce
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data_nonce' in response.data)

    def test_new_recoverycode_with_recovery_data_nonce_not_in_hex(self):
        """
        Tests to create a new recoverycode with recovery_data_nonce not in hex
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788',
            'recovery_data_nonce ': '123456788X',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_data_nonce' in response.data)

    def test_new_recoverycode_with_empty_recovery_sauce(self):
        """
        Tests to create a new recoverycode with an empty recovery_sauce
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_sauce' in response.data)

    def test_new_recoverycode_with_no_recovery_sauce(self):
        """
        Tests to create a new recoverycode with no recovery_sauce
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': '123456678',
            'recovery_data': '123456788',
            'recovery_data_nonce ': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_sauce' in response.data)

    def test_new_recoverycode_without_authentication(self):
        """
        Tests to create a new recoverycode without authentication
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': 'asdf',
            'recovery_data': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_new_recoverycode(self):
        """
        Tests to create a new recoverycode
        """

        url = reverse('recoverycode')

        data = {
            'recovery_authkey': 'asdf',
            'recovery_data': '123456678',
            'recovery_data_nonce ': '123456788',
            'recovery_sauce': '123456788',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue('recovery_code_id' in response.data)



    def test_delete_recoverycode(self):
        """
        Tests POST method on recoverycode
        """

        url = reverse('recoverycode')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)



class PasswordTests(APITestCaseExtended):
    def setUp(self):
        self.verifier_private_key = '4491f6c03d8196d65f45f7f6ab693088b1e8cd14e728201e5cca8333f2a88b4e'
        self.verifier_public_key = '7a372bb1558b0d42eaac3e238e633efd997f6496c62302bdb56c3a729a7ce41c'

        self.user_public_key = '618ccedc6edc9ee8110f8a75e7bb24238759fe43f638ad41d399dae7043f9d1d'
        self.user_private_key = '07b04506e36faf9c2b478383e7db6b54b6674322d8eadc9d2c1e4aa15390e315'


        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '1f3f3c0f4c8a52fb0d83144bb4e7aaf04d552d43ec7a60792654ef664af17dad'
        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey=make_password(self.test_authkey),
            public_key=self.user_public_key,
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
        self.test_authkey2 = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_private_key2 = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key2 = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce2 = 'fbcd7106abf5ef076af9a1ab59e98ff5f4f81f524ede6d7155500e059b25b8b0'
        self.test_user_obj2 = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey=make_password(self.test_authkey2),
            public_key=self.user_public_key,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

        self.test_email3 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt3 = 'c'
        self.test_username3 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey3 = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_private_key3 = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce3 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key3 = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce3 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce3 = 'de6096562c48b5f58aaabfa9dfab3a59930daf57aa50f53a4d80d8205a91ba17'
        self.test_user_obj3 = models.User.objects.create(
            email=self.test_email3,
            email_bcrypt=self.test_email_bcrypt3,
            username=self.test_username3,
            authkey=make_password(self.test_authkey3),
            public_key=self.user_public_key,
            private_key=self.test_private_key3,
            private_key_nonce=self.test_private_key_nonce3,
            secret_key=self.test_secret_key3,
            secret_key_nonce=self.test_secret_key_nonce3,
            user_sauce=self.test_user_sauce3,
            is_email_active=True
        )

        self.test_recovery_authkey = 'asdf'
        self.test_recovery_data = 'test_recovery_data'
        self.test_recovery_data_nonce = 'test_recovery_data_nonce'
        self.test_recovery_sauce = 'test_recovery_sauce'

        self.test_recovery_code_obj = models.Recovery_Code.objects.create(
            user = self.test_user_obj,
            recovery_authkey = make_password(self.test_recovery_authkey),
            recovery_data = readbuffer(self.test_recovery_data),
            recovery_data_nonce = self.test_recovery_data_nonce,
            verifier = self.verifier_private_key,
            verifier_issue_date = timezone.now(),
            recovery_sauce = self.test_recovery_sauce
        )

        self.test_recovery_authkey2 = 'asdf123'
        self.test_recovery_data2 = 'test_recovery_data2'
        self.test_recovery_data_nonce2 = 'test_recovery_data_nonce2'
        self.test_recovery_sauce2 = 'test_recovery_sauce2'

        self.test_recovery_code_obj_expired = models.Recovery_Code.objects.create(
            user = self.test_user_obj3,
            recovery_authkey = make_password(self.test_recovery_authkey2),
            recovery_data = readbuffer(self.test_recovery_data2),
            recovery_data_nonce = self.test_recovery_data_nonce2,
            verifier = self.verifier_private_key,
            verifier_issue_date = timezone.now() - datetime.timedelta(0, settings.RECOVERY_VERIFIER_TIME_VALID),
            recovery_sauce = self.test_recovery_sauce2
        )



    def test_get_password(self):
        """
        Tests GET method on password
        """

        url = reverse('password')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_password_with_no_username(self):
        """
        Tests PUT method on password with no username
        """

        url = reverse('password')

        data = {
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': 'C6B13DB4699FF60CF0C60E38C5130500E62235C152FD6129D801CDDCF0604C7D',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF77',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('username' in response.data)

    def test_put_password_with_no_recovery_authkey(self):
        """
        Tests PUT method on password with no recovery authkey
        """

        url = reverse('password')

        data = {
            'username': self.test_username,
            'update_data': 'C6B13DB4699FF60CF0C60E38C5130500E62235C152FD6129D801CDDCF0604C7D',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF77',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_authkey' in response.data)

    def test_put_password_with_no_email_like_username(self):
        """
        Tests PUT method on password with no email like username
        """

        url = reverse('password')

        data = {
            'username': 'username',
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': 'C6B13DB4699FF60CF0C60E38C5130500E62235C152FD6129D801CDDCF0604C7D',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF77',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('username' in response.data)

    def test_put_password_with_incorrect_username(self):
        """
        Tests PUT method on password with incorrect username
        """

        url = reverse('password')

        data = {
            'username': 'asdf@asdf.com',
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': 'C6B13DB4699FF60CF0C60E38C5130500E62235C152FD6129D801CDDCF0604C7D',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF77',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_password_with_incorrect_authkey(self):
        """
        Tests PUT method on password with incorrect authkey
        """

        url = reverse('password')

        data = {
            'username': self.test_username,
            'recovery_authkey': 'WrongAuthKey',
            'update_data': 'C6B13DB4699FF60CF0C60E38C5130500E62235C152FD6129D801CDDCF0604C7D',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF77',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_password_with_user_who_has_no_recovery_key(self):
        """
        Tests PUT method on password with user who has no recovery key
        """

        url = reverse('password')

        data = {
            'username': self.test_username2,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': 'C6B13DB4699FF60CF0C60E38C5130500E62235C152FD6129D801CDDCF0604C7D',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF77',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_put_password_with_expired_recovery_code_verifier(self):
        """
        Tests PUT method on password with expired recovery code verifier
        """

        url = reverse('password')

        data = {
            'username': self.test_username3,
            'recovery_authkey': self.test_recovery_authkey2,
            'update_data': 'C6B13DB4699FF60CF0C60E38C5130500E62235C152FD6129D801CDDCF0604C7D',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF77',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_put_password_with_missing_authkey(self):
        """
        Tests PUT method on password with missing authkey
        """

        url = reverse('password')

        update_data_nonce = nacl.utils.random(Box.NONCE_SIZE)
        update_data_nonce_hex = nacl.encoding.HexEncoder.encode(update_data_nonce)

        crypto_box = Box(PrivateKey(self.user_private_key, encoder=nacl.encoding.HexEncoder),
                         PublicKey(self.verifier_public_key, encoder=nacl.encoding.HexEncoder))


        update_data_dec = crypto_box.encrypt(json.dumps({
            'private_key': 'private_key',
            'private_key_nonce': 'private_key_nonce',
            'secret_key': 'secret_key',
            'secret_key_nonce': 'secret_key_nonce',
        }).encode("utf-8"), update_data_nonce)

        update_data = update_data_dec[len(update_data_nonce):]
        update_data_hex = nacl.encoding.HexEncoder.encode(update_data)

        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': update_data_hex.decode(),
            'update_data_nonce': update_data_nonce_hex.decode(),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_put_password_with_missing_private_key(self):
        """
        Tests PUT method on password with missing private_key
        """

        url = reverse('password')

        update_data_nonce = nacl.utils.random(Box.NONCE_SIZE)
        update_data_nonce_hex = nacl.encoding.HexEncoder.encode(update_data_nonce)

        crypto_box = Box(PrivateKey(self.user_private_key, encoder=nacl.encoding.HexEncoder),
                         PublicKey(self.verifier_public_key, encoder=nacl.encoding.HexEncoder))


        update_data_dec = crypto_box.encrypt(json.dumps({
            'authkey': 'authkey',
            'private_key_nonce': 'private_key_nonce',
            'secret_key': 'secret_key',
            'secret_key_nonce': 'secret_key_nonce',
        }).encode("utf-8"), update_data_nonce)

        update_data = update_data_dec[len(update_data_nonce):]
        update_data_hex = nacl.encoding.HexEncoder.encode(update_data)

        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': update_data_hex.decode(),
            'update_data_nonce': update_data_nonce_hex.decode(),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_put_password_with_missing_private_key_nonce(self):
        """
        Tests PUT method on password with missing private_key_nonce
        """

        url = reverse('password')

        update_data_nonce = nacl.utils.random(Box.NONCE_SIZE)
        update_data_nonce_hex = nacl.encoding.HexEncoder.encode(update_data_nonce)

        crypto_box = Box(PrivateKey(self.user_private_key, encoder=nacl.encoding.HexEncoder),
                         PublicKey(self.verifier_public_key, encoder=nacl.encoding.HexEncoder))


        update_data_dec = crypto_box.encrypt(json.dumps({
            'authkey': 'authkey',
            'private_key': 'private_key',
            'secret_key': 'secret_key',
            'secret_key_nonce': 'secret_key_nonce',
        }).encode("utf-8"), update_data_nonce)

        update_data = update_data_dec[len(update_data_nonce):]
        update_data_hex = nacl.encoding.HexEncoder.encode(update_data)

        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': update_data_hex.decode(),
            'update_data_nonce': update_data_nonce_hex.decode(),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_put_password_with_missing_secret_key(self):
        """
        Tests PUT method on password with missing secret_key
        """

        url = reverse('password')

        update_data_nonce = nacl.utils.random(Box.NONCE_SIZE)
        update_data_nonce_hex = nacl.encoding.HexEncoder.encode(update_data_nonce)

        crypto_box = Box(PrivateKey(self.user_private_key, encoder=nacl.encoding.HexEncoder),
                         PublicKey(self.verifier_public_key, encoder=nacl.encoding.HexEncoder))


        update_data_dec = crypto_box.encrypt(json.dumps({
            'authkey': 'authkey',
            'private_key': 'private_key',
            'private_key_nonce': 'private_key_nonce',
            'secret_key_nonce': 'secret_key_nonce',
        }).encode("utf-8"), update_data_nonce)

        update_data = update_data_dec[len(update_data_nonce):]
        update_data_hex = nacl.encoding.HexEncoder.encode(update_data)

        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': update_data_hex.decode(),
            'update_data_nonce': update_data_nonce_hex.decode(),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_put_password_with_missing_secret_key_nonce(self):
        """
        Tests PUT method on password with missing secret_key_nonce
        """

        url = reverse('password')

        update_data_nonce = nacl.utils.random(Box.NONCE_SIZE)
        update_data_nonce_hex = nacl.encoding.HexEncoder.encode(update_data_nonce)

        crypto_box = Box(PrivateKey(self.user_private_key, encoder=nacl.encoding.HexEncoder),
                         PublicKey(self.verifier_public_key, encoder=nacl.encoding.HexEncoder))


        update_data_dec = crypto_box.encrypt(json.dumps({
            'authkey': 'authkey',
            'private_key': 'private_key',
            'private_key_nonce': 'private_key_nonce',
            'secret_key': 'secret_key',
        }).encode("utf-8"), update_data_nonce)

        update_data = update_data_dec[len(update_data_nonce):]
        update_data_hex = nacl.encoding.HexEncoder.encode(update_data)

        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': update_data_hex.decode(),
            'update_data_nonce': update_data_nonce_hex.decode(),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_put_password_with_invalid_json(self):
        """
        Tests PUT method on password with invalid json
        """

        url = reverse('password')

        update_data_nonce = nacl.utils.random(Box.NONCE_SIZE)
        update_data_nonce_hex = nacl.encoding.HexEncoder.encode(update_data_nonce)

        crypto_box = Box(PrivateKey(self.user_private_key, encoder=nacl.encoding.HexEncoder),
                         PublicKey(self.verifier_public_key, encoder=nacl.encoding.HexEncoder))


        update_data_dec = crypto_box.encrypt('narf'.encode("utf-8"), update_data_nonce)

        update_data = update_data_dec[len(update_data_nonce):]
        update_data_hex = nacl.encoding.HexEncoder.encode(update_data)

        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': update_data_hex.decode(),
            'update_data_nonce': update_data_nonce_hex.decode(),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_put_password_with_no_validation(self):
        """
        Tests PUT method on password with no validation
        """

        url = reverse('password')


        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': 'C6B13DB4699FF60CF0C60E38C5130500E62235C152FD6129D801CDDCF0604C7D',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF77',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_put_password_with_update_data_being_no_hex(self):
        """
        Tests PUT method on password with update_data being no hex
        """

        url = reverse('password')


        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': 'X',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF77',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_put_password_with_update_data_nonce_being_no_hex(self):
        """
        Tests PUT method on password with update_data being no hex
        """

        url = reverse('password')


        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': 'C6B13DB4699FF60CF0C60E38C5130500E62235C152FD6129D801CDDCF0604C7D',
            'update_data_nonce': '39F0F10BFC6497F74563127CA08B8DC3A8729B789BB463AF0A3B6BD1CEE9DF7X',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_put_password(self):
        """
        Tests PUT method on password
        """

        url = reverse('password')

        update_data_nonce = nacl.utils.random(Box.NONCE_SIZE)
        update_data_nonce_hex = nacl.encoding.HexEncoder.encode(update_data_nonce).decode()

        crypto_box = Box(PrivateKey(self.user_private_key, encoder=nacl.encoding.HexEncoder),
                         PublicKey(self.verifier_public_key, encoder=nacl.encoding.HexEncoder))

        new_authkey = 'authkey'
        new_private_key = 'private_key'
        new_private_key_nonce = 'private_key_nonce'
        new_secret_key = 'secret_key'
        new_secret_key_nonce = 'secret_key_nonce'

        update_data_dec = crypto_box.encrypt(json.dumps({
            'authkey': new_authkey,
            'private_key': new_private_key,
            'private_key_nonce': new_private_key_nonce,
            'secret_key': new_secret_key,
            'secret_key_nonce': new_secret_key_nonce,
        }).encode("utf-8"), update_data_nonce)

        update_data = update_data_dec[len(update_data_nonce):]
        update_data_hex = nacl.encoding.HexEncoder.encode(update_data).decode()

        data = {
            'username': self.test_username,
            'recovery_authkey': self.test_recovery_authkey,
            'update_data': update_data_hex,
            'update_data_nonce': update_data_nonce_hex,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Update was accepted, now lets check that the old verifier details have been deleted in the database and the
        # user details like authkey and private / secret key have been updated

        db_user = models.User.objects.get(pk=self.test_user_obj.id)

        self.assertEqual(db_user.private_key, new_private_key)
        self.assertEqual(db_user.private_key_nonce, new_private_key_nonce)
        self.assertEqual(db_user.secret_key, new_secret_key)
        self.assertEqual(db_user.secret_key_nonce, new_secret_key_nonce)
        self.assertTrue(check_password(new_authkey, db_user.authkey))

        db_recovery_code = models.Recovery_Code.objects.get(pk=self.test_recovery_code_obj.id)

        self.assertEqual(db_recovery_code.verifier, '')
        self.assertIsNone(db_recovery_code.verifier_issue_date)


    def test_post_password_with_no_username(self):
        """
        Tests POST method on password with no username
        """

        url = reverse('password')

        data = {
            'recovery_authkey': self.test_recovery_authkey,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)


        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('username' in response.data)

    def test_post_password_with_no_recovery_authkey(self):
        """
        Tests POST method on password with no recovery authkey
        """

        url = reverse('password')

        data = {
            'username': self.test_username,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)


        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('recovery_authkey' in response.data)

    def test_post_password_with_no_email_like_username(self):
        """
        Tests POST method on password with no email like username
        """

        url = reverse('password')

        data = {
            'recovery_authkey': self.test_recovery_authkey,
            'username': 'username',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('username' in response.data)

    def test_post_password_with_incorrect_username(self):
        """
        Tests POST method on password with incorrect username
        """

        url = reverse('password')

        data = {
            'recovery_authkey': self.test_recovery_authkey,
            'username': 'asdf@asdf.com',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_password_with_incorrect_authkey(self):
        """
        Tests POST method on password with incorrect authkey
        """

        url = reverse('password')

        data = {
            'recovery_authkey': 'WrongAuthKey',
            'username': self.test_username,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_password_with_user_who_has_no_recovery_key(self):
        """
        Tests POST method on password with user who has no recovery key
        """

        url = reverse('password')

        data = {
            'recovery_authkey': self.test_recovery_authkey,
            'username': self.test_username2,
        }

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_password(self):
        """
        Tests POST method on password
        """

        url = reverse('password')

        data = {
            'recovery_authkey': self.test_recovery_authkey,
            'username': self.test_username,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue('recovery_data' in response.data)
        self.assertEqual(response.data['recovery_data'], self.test_recovery_data)
        self.assertTrue('recovery_data_nonce' in response.data)
        self.assertEqual(response.data['recovery_data_nonce'], self.test_recovery_data_nonce)
        self.assertTrue('user_sauce' in response.data)
        self.assertEqual(response.data['user_sauce'], self.test_user_sauce)
        self.assertTrue('verifier_time_valid' in response.data)
        self.assertEqual(response.data['verifier_time_valid'], settings.RECOVERY_VERIFIER_TIME_VALID)
        self.assertTrue('recovery_sauce' in response.data)
        self.assertEqual(response.data['recovery_sauce'], self.test_recovery_sauce)
        self.assertTrue('verifier_public_key' in response.data)
        self.assertEqual(len(response.data['verifier_public_key']), 64)

    def test_delete_password(self):
        """
        Tests DELETE method on password
        """

        url = reverse('password')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)



