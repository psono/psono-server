from django.urls import reverse
from django.conf import settings
from django.utils import timezone
from rest_framework import status

import random
import string
import binascii
import os

from restapi import models
from restapi.tests.base import APITestCaseExtended


class ReadRecoveryCodeTests(APITestCaseExtended):
    def setUp(self):
        self.verifier_private_key = '4491f6c03d8196d65f45f7f6ab693088b1e8cd14e728201e5cca8333f2a88b4e'
        self.verifier_public_key = '7a372bb1558b0d42eaac3e238e633efd997f6496c62302bdb56c3a729a7ce41c'

        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@example.com'
        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@example.com'
        self.test_email3 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test3@example.com'
        self.test_email_bcrypt = 'a'
        self.test_email_bcrypt2 = 'b'
        self.test_email_bcrypt3 = 'c'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test1@psono.pw'
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test2@psono.pw'
        self.test_username3 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test3@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_private_key_nonce3 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce3 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '6df1f310730e5464ce23e05fa4eca0de3fe30805fc8cc1d6b37389262e4bd9c3'
        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

        self.test_user_obj2 = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

        self.test_recovery_authkey = 'asdf'
        self.test_recovery_data = 'test_recovery_data'
        self.test_recovery_data_nonce = 'test_recovery_data_nonce'
        self.test_recovery_sauce = 'test_recovery_sauce'

        self.test_recovery_code_obj = models.Recovery_Code.objects.create(
            user = self.test_user_obj,
            recovery_authkey = "abc",
            recovery_data = self.test_recovery_data.encode(),
            recovery_data_nonce = self.test_recovery_data_nonce,
            verifier = self.verifier_private_key,
            verifier_issue_date = timezone.now(),
            recovery_sauce = self.test_recovery_sauce
        )

        self.test_recovery_authkey2 = 'asdf123'
        self.test_recovery_data2 = 'test_recovery_data2'
        self.test_recovery_data_nonce2 = 'test_recovery_data_nonce2'
        self.test_recovery_sauce2 = 'test_recovery_sauce2'

        self.test_recovery_code_obj2 = models.Recovery_Code.objects.create(
            user = self.test_user_obj,
            recovery_authkey = "abc",
            recovery_data = self.test_recovery_data2.encode(),
            recovery_data_nonce = self.test_recovery_data_nonce2,
            verifier = self.verifier_private_key,
            verifier_issue_date = timezone.now(),
            recovery_sauce = self.test_recovery_sauce2
        )

        self.admin = models.User.objects.create(
            email=self.test_email3,
            email_bcrypt=self.test_email_bcrypt3,
            username=self.test_username3,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce3,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce3,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            is_superuser=True
        )


    def test_read_recovery_code_success(self):
        """
        Tests GET method on recovery_code
        """

        url = reverse('admin_recovery_code')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['recovery_codes']), 2)

class CreateRecoveryCodeTests(APITestCaseExtended):
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
            authkey="abc",
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            is_superuser=True
        )



    def test_create_recovery_code(self):
        """
        Tests POST method on recovery_code
        """

        url = reverse('admin_recovery_code')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

class UpdateRecoveryCodeTests(APITestCaseExtended):
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
            authkey="abc",
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            is_superuser=True
        )



    def test_update_recovery_code(self):
        """
        Tests PUT method on recovery_code
        """

        url = reverse('admin_recovery_code')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

class DeleteRecoveryCodeTests(APITestCaseExtended):
    def setUp(self):
        self.verifier_private_key = '4491f6c03d8196d65f45f7f6ab693088b1e8cd14e728201e5cca8333f2a88b4e'
        self.verifier_public_key = '7a372bb1558b0d42eaac3e238e633efd997f6496c62302bdb56c3a729a7ce41c'

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
            authkey="abc",
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce,
            is_email_active=True,
            is_superuser=True
        )

        self.test_recovery_authkey = 'asdf'
        self.test_recovery_data = 'test_recovery_data'
        self.test_recovery_data_nonce = 'test_recovery_data_nonce'
        self.test_recovery_sauce = 'test_recovery_sauce'

        self.test_recovery_code_obj = models.Recovery_Code.objects.create(
            user = self.test_user_obj,
            recovery_authkey = "abc",
            recovery_data = self.test_recovery_data.encode(),
            recovery_data_nonce = self.test_recovery_data_nonce,
            verifier = self.verifier_private_key,
            verifier_issue_date = timezone.now(),
            recovery_sauce = self.test_recovery_sauce
        )

        self.test_recovery_authkey2 = 'asdf123'
        self.test_recovery_data2 = 'test_recovery_data2'
        self.test_recovery_data_nonce2 = 'test_recovery_data_nonce2'
        self.test_recovery_sauce2 = 'test_recovery_sauce2'

        self.test_recovery_code_obj2 = models.Recovery_Code.objects.create(
            user = self.test_user_obj,
            recovery_authkey = "abc",
            recovery_data = self.test_recovery_data2.encode(),
            recovery_data_nonce = self.test_recovery_data_nonce2,
            verifier = self.verifier_private_key,
            verifier_issue_date = timezone.now(),
            recovery_sauce = self.test_recovery_sauce2
        )


    def test_delete_recovery_code_success(self):
        """
        Tests DELETE method on recovery_code
        """

        url = reverse('admin_recovery_code')

        data = {
            'recovery_code_id': self.test_recovery_code_obj.id
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.Duo.objects.all().count(), 0)


    def test_delete_recovery_code_failure_no_admin(self):
        """
        Tests DELETE method on recovery_code without being an admin
        """

        url = reverse('admin_recovery_code')

        data = {
            'recovery_code_id': self.test_recovery_code_obj.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_delete_recovery_code_failure_no_recovery_code_id(self):
        """
        Tests DELETE method on recovery_code without a recovery_code id
        """

        url = reverse('admin_recovery_code')

        data = {
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_recovery_code_failure_recovery_code_id_not_exist(self):
        """
        Tests DELETE method on recovery_code with a recovery_code id that does not exist
        """

        url = reverse('admin_recovery_code')

        data = {
            'recovery_code_id': '499d3c84-e8ae-4a6b-a4c2-43c79beb069a'
        }

        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)