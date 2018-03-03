from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from rest_framework import status

import random
import string
import binascii
import os

from restapi import models
from restapi.tests.base import APITestCaseExtended


class DeleteYubikeyOTPTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@example.com'
        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@example.com'
        self.test_email_bcrypt = 'a'
        self.test_email_bcrypt2 = 'b'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@psono.pw'
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
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

        self.admin = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            is_superuser=True
        )

        self.yubikey_otp = models.Yubikey_OTP.objects.create(
                user=self.test_user_obj,
                title= 'My TItle',
                yubikey_id = '1234'
        )


    def test_delete_yubikey_otp_success(self):
        """
        Tests DELETE method on yubikey_otp
        """

        url = reverse('admin_yubikey_otp')

        data = {
            'yubikey_otp_id': self.yubikey_otp.id
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.Yubikey_OTP.objects.all().count(), 0)


    def test_delete_yubikey_otp_failure_no_admin(self):
        """
        Tests DELETE method on yubikey_otp without being an admin
        """

        url = reverse('admin_yubikey_otp')

        data = {
            'yubikey_otp_id': self.yubikey_otp.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_delete_yubikey_otp_failure_no_yubikey_otp_id(self):
        """
        Tests DELETE method on yubikey_otp without a yubikey_otp id
        """

        url = reverse('admin_yubikey_otp')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_yubikey_otp_failure_yubikey_otp_id_not_exist(self):
        """
        Tests DELETE method on yubikey_otp with a yubikey_otp id that does not exist
        """

        url = reverse('admin_yubikey_otp')

        data = {
            'yubikey_otp_id': '499d3c84-e8ae-4a6b-a4c2-43c79beb069a'
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

