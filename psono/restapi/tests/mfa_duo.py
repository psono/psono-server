from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework import status

from datetime import timedelta
from mock import patch
import random
import string
import binascii
import os
import hashlib
import time

from restapi import models
from .base import APITestCaseExtended
from ..utils import encrypt_with_db_secret


class DuoVerifyTests(APITestCaseExtended):
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
        self.session_secret_key = hashlib.sha256(settings.DB_SECRET.encode()).hexdigest()
        models.Token.objects.create(
            key= hashlib.sha512(self.token.encode()).hexdigest(),
            user=self.test_user_obj,
            secret_key=self.session_secret_key,
            valid_till = timezone.now() + timedelta(seconds=10)
        )

        models.Duo.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            duo_integration_key = 'duo_integration_key',
            duo_secret_key = encrypt_with_db_secret('duo_secret_key'),
            duo_host = 'duo_secret_key',
            enrollment_user_id = 'enrollment_user_id',
            enrollment_activation_code = 'enrollment_activation_code',
            enrollment_expiration_date = timezone.now() + timedelta(seconds=600),
        )

    def test_get_authentication_duo_verify(self):
        """
        Tests GET method on authentication_duo_verify
        """

        url = reverse('authentication_duo_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_duo_verify(self):
        """
        Tests PUT method on authentication_duo_verify
        """

        url = reverse('authentication_duo_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def mock_check(self):
        return {
            'time': int(time.time())
        }

    def mock_enroll_status(self, user_id=None, activation_code=None):
        return 'success'


    def mock_auth_valid(self, user_id=None, factor=None, device=None, pushinfo=None, passcode=None, async=False):
        return {
            'result': 'allow'
        }
    def mock_auth_invalid(self, user_id=None, factor=None, device=None, pushinfo=None, passcode=None, async=False):
        return {
            'result': 'deny'
        }

    @patch('duo_client.Auth.check', mock_check)
    @patch('duo_client.Auth.enroll_status', mock_enroll_status)
    @patch('duo_client.Auth.auth', mock_auth_valid)
    def test_post_authentication_duo_verify(self):
        """
        Tests POST method on authentication_duo_verify
        """

        url = reverse('authentication_duo_verify')

        data = {
            'token': self.token,
            'duo_token': '123456'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch('duo_client.Auth.check', mock_check)
    @patch('duo_client.Auth.enroll_status', mock_enroll_status)
    @patch('duo_client.Auth.auth', mock_auth_valid)
    def test_post_authentication_duo_verify_invalid_token(self):
        """
        Tests POST method on authentication_duo_verify with invalid token
        """

        url = reverse('authentication_duo_verify')

        data = {
            'token': '12345',
            'duo_token': '123456'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + '12345')
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('duo_client.Auth.check', mock_check)
    @patch('duo_client.Auth.enroll_status', mock_enroll_status)
    @patch('duo_client.Auth.auth', mock_auth_invalid)
    def test_post_authentication_duo_verify_invalid_duo_token(self):
        """
        Tests POST method on authentication_duo_verify with an invalid duo_token
        """

        url = reverse('authentication_duo_verify')

        data = {
            'token': self.token,
            'duo_token': '123456'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotEqual(response.data.get('non_field_errors', False), False)

    def test_delete_authentication_duo_verify(self):
        """
        Tests DELETE method on authentication_duo_verify
        """

        url = reverse('authentication_duo_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)



class DuoTests(APITestCaseExtended):
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

    def test_get_user_duo(self):
        """
        Tests GET method on user_duo
        """

        duo = models.Duo.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            duo_integration_key = 'duo_integration_key',
            duo_secret_key = encrypt_with_db_secret('duo_secret_key'),
            duo_host = 'duo_secret_key',
            enrollment_user_id = 'enrollment_user_id',
            enrollment_activation_code = 'enrollment_activation_code',
            enrollment_expiration_date = timezone.now() + timedelta(seconds=600),
        )

        url = reverse('user_duo')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.data, {
            "duos":[{
                "id":duo.id,
                "title":"My Sweet Title"
            }]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def mock_check(self):
        return {
            'time': int(time.time())
        }

    def mock_enroll(self, username=None):
        return {
            'expiration': int(time.time()) + 86400,
            'user_id': '1234',
            'activation_code': '123456',
        }

    @patch('duo_client.Auth.check', mock_check)
    @patch('duo_client.Auth.enroll', mock_enroll)
    def test_put_user_duo(self):
        """
        Tests PUT method on user_duo
        """

        url = reverse('user_duo')

        data = {
            'title': 'asdu5zz53',
            'integration_key': 'integration_key',
            'secret_key': 'secret_key',
            'host': 'host',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('id', False), False)
        self.assertNotEqual(response.data.get('activation_code', False), False)


    @patch('duo_client.Auth.check', mock_check)
    @patch('duo_client.Auth.enroll', mock_enroll)
    def test_put_user_duo_no_title(self):
        """
        Tests PUT method on user_duo with no title
        """

        url = reverse('user_duo')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_user_duo_no_parameters(self):
        """
        Tests POST method on user_duo
        """

        url = reverse('user_duo')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def mock_enroll_status(self, user_id=None, activation_code=None):
        return 'success'

    def mock_auth_valid(self, user_id=None, factor=None, device=None, pushinfo=None, passcode=None, async=False):
        return {
            'result': 'allow'
        }

    @patch('duo_client.Auth.check', mock_check)
    @patch('duo_client.Auth.enroll_status', mock_enroll_status)
    @patch('duo_client.Auth.auth', mock_auth_valid)
    def test_activate_duo_success(self):
        """
        Tests POST method on user_duo to activate a duo
        """

        duo = models.Duo.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            duo_integration_key = 'duo_integration_key',
            duo_secret_key = encrypt_with_db_secret('duo_secret_key'),
            duo_host = 'duo_secret_key',
            enrollment_user_id = 'enrollment_user_id',
            enrollment_activation_code = 'enrollment_activation_code',
            enrollment_expiration_date = timezone.now() + timedelta(seconds=600),
            active = False,
        )

        url = reverse('user_duo')

        data = {
            'duo_id': duo.id,
            'duo_token': '123456',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        db_duo = models.Duo.objects.get(pk=duo.id)
        self.assertTrue(db_duo.active)

    def test_delete_user_duo(self):
        """
        Tests DELETE method on user_duo
        """

        duo = models.Duo.objects.create(
            user=self.test_user_obj,
            title= 'My Sweet Title',
            duo_integration_key = 'duo_integration_key',
            duo_secret_key = encrypt_with_db_secret('duo_secret_key'),
            duo_host = 'duo_secret_key',
            enrollment_user_id = 'enrollment_user_id',
            enrollment_activation_code = 'enrollment_activation_code',
            enrollment_expiration_date = timezone.now() + timedelta(seconds=600),
        )

        url = reverse('user_duo')

        data = {
            'duo_id': duo.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.data, {
            "duos":[]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_user_duo_no_duo_id (self):
        """
        Tests DELETE method on user_duo with no duo_id
        """

        url = reverse('user_duo')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_user_duo_duo_id_no_uuid(self):
        """
        Tests DELETE method on user_duo with duo_id not being a uuid
        """

        url = reverse('user_duo')

        data = {
            'duo_id': '12345'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_user_duo_duo_id_not_exist(self):
        """
        Tests DELETE method on user_duo with duo_id not existing
        """

        url = reverse('user_duo')

        data = {
            'duo_id': '7e866c32-3e4d-4421-8a7d-3ac62f980fd3'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

