from django.urls import reverse
from django.conf import settings
from django.utils import timezone
from rest_framework import status
from django.test.utils import override_settings

from datetime import timedelta
from mock import patch, Mock
import random
import string
import binascii
import os
import hashlib
import json

import nacl.encoding
import nacl.utils
import nacl.secret

from restapi import models
from .base import APITestCaseExtended
from ..utils import encrypt_with_db_secret, decrypt_with_db_secret


class IvaltVerifyTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = self.test_authkey = '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678'
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
            authkey="abc",
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
        self.token_obj = models.Token.objects.create(
            key= hashlib.sha512(self.token.encode()).hexdigest(),
            user=self.test_user_obj,
            secret_key=self.session_secret_key,
            valid_till = timezone.now() + timedelta(seconds=10)
        )

        self.ivalt = models.Ivalt.objects.create(
            user=self.test_user_obj,
            mobile = encrypt_with_db_secret('0123456789'),
        )


        # encrypt authorization validator with session key
        secret_box = nacl.secret.SecretBox(self.session_secret_key, encoder=nacl.encoding.HexEncoder)
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        self.authorization_validator = json.dumps({
            'text': authorization_validator_hex.decode(),
            'nonce': authorization_validator_nonce_hex.decode(),
        })

    def test_get_authentication_ivalt_verify(self):
        """
        Tests GET method on authentication_ivalt_verify
        """

        url = reverse('authentication_ivalt_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_authentication_ivalt_verify(self):
        """
        Tests PUT method on authentication_ivalt_verify
        """

        url = reverse('authentication_ivalt_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_post_authentication_ivalt_verify_invalid_token(self):
        """
        Tests POST method on authentication_ivalt_verify with invalid token
        """

        url = reverse('authentication_ivalt_verify')

        data = {
            'token': '12345',
            'rquest_type': 'notification'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + '12345', HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    

    def mock_verify_notification_success(self, url=None, json=None, headers=None, timeout=None):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"status": True, "message": "Biometric Auth Request successfully sent.", "details": None }}
        return mock_response

    @patch('restapi.utils.ivalt.requests.post', mock_verify_notification_success)
    def test_authentication_ivalt_verify_notification_sent_success(self):
        """
        Tests POST method on authentication_ivalt_verify
        """

        url = reverse('authentication_ivalt_verify')

        data = {
            'token': self.token,
            'request_type': 'notification'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_authentication_ivalt_verify_notification_sent_invalid_request_type(self):
        """
        Tests POST method on authentication_ivalt_verify
        """

        url = reverse('authentication_ivalt_verify')

        data = {
            'token': self.token,
            'request_type': 'other'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors')[0], 'INAVLID_VALUE_FOR_REQUEST_TYPE')

    def mock_verify_verification_success(self, url=None, json=None, headers=None, timeout=None):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": { "status": True, "message": "Biometric Authentication successfully done.", "details": { "id": 1111, "name": "user_name", "email": "user_email", "country_code": "country_code", "mobile": "user_mobile", "latitude": "latitude", "longitude": "longitude", "imei": "imei", "address": "user_address" }}}
        return mock_response

    def mock_verify_verification_pending(self, url=None, json=None, headers=None, timeout=None):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": { "type": "https://httpstatuses.com/404", "title": "Not Found", "status": 404, "detail": "The mobile number provided (+910123456789) was not found."}}
        return mock_response
    
    def mock_verify_verification_invalid_time_window(self, url=None, json=None, headers=None, timeout=None):
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"error": { "type": "https://httpstatuses.com/403", "title": "Invalid details", "status": 403, "detail": "You are not within the timezone."}}
        return mock_response
    
    def mock_verify_verification_invalid_geo_fance(self, url=None, json=None, headers=None, timeout=None):
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"error": { "type": "https://httpstatuses.com/403", "title": "Invalid details", "status": 403, "detail": "You are not within the geofencing location."}}
        return mock_response

    @patch('restapi.utils.ivalt.requests.post', mock_verify_verification_success)
    def test_authentication_ivalt_verify_verification_success(self):
        """
        Tests POST method on authentication_ivalt_verify
        """

        url = reverse('authentication_ivalt_verify')

        data = {
            'token': self.token,
            'request_type': 'verification'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch('restapi.utils.ivalt.requests.post', mock_verify_verification_pending)
    def test_authentication_ivalt_verify_verification_pending(self):
        """
        Tests POST method on authentication_ivalt_verify

        waiting for user's authenication using ivalt mobile app
        """

        url = reverse('authentication_ivalt_verify')

        data = {
            'token': self.token,
            'request_type': 'verification'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    @patch('restapi.utils.ivalt.requests.post', mock_verify_verification_invalid_time_window)
    def test_authentication_ivalt_verify_verification_failed_invalid_time_window(self):
        """
        Tests POST method on authentication_ivalt_verify

        waiting for user's authenication using ivalt mobile app
        """

        url = reverse('authentication_ivalt_verify')

        data = {
            'token': self.token,
            'request_type': 'verification'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('restapi.utils.ivalt.requests.post', mock_verify_verification_invalid_geo_fance)
    def test_authentication_ivalt_verify_verification_failed_invalid_geo_fance(self):
        """
        Tests POST method on authentication_ivalt_verify

        waiting for user's authenication using ivalt mobile app
        """

        url = reverse('authentication_ivalt_verify')

        data = {
            'token': self.token,
            'request_type': 'verification'
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token, HTTP_AUTHORIZATION_VALIDATOR=self.authorization_validator)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_authentication_ivalt_verify(self):
        """
        Tests DELETE method on authentication_ivalt_verify
        """

        url = reverse('authentication_ivalt_verify')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)



class IvaltTests(APITestCaseExtended):

    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = self.test_authkey = '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678'
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

    @override_settings(IVALT_SECRET_KEY="abc")
    def test_get_user_ivalt(self):
        """
        Tests GET method on user_ivalt
        """

        ivalt = models.Ivalt.objects.create(
            user=self.test_user_obj,
            mobile = encrypt_with_db_secret('+10123456789'),
        )

        url = reverse('user_ivalt')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.data, {
            "ivalt":[{
                'id': ivalt.id,
                'active': ivalt.active,
                'mobile': decrypt_with_db_secret(ivalt.mobile),
            }]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)    
    
    def mock_verify_notification_success(self, url=None, json=None, headers=None, timeout=None):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"status": True, "message": "Biometric Auth Request successfully sent.", "details": None }}
        return mock_response

    @override_settings(IVALT_SECRET_KEY="abc")
    @patch('restapi.utils.ivalt.requests.post', mock_verify_notification_success)
    def test_put_user_ivalt(self):
        """
        Tests PUT method on user_ivalt to create a new ivalt 2fa
        """

        url = reverse('user_ivalt')

        data = {
            'mobile': '+10123456789',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('id', False), False)

    @override_settings(IVALT_SECRET_KEY="abc")
    def test_put_user_ivalt_error_already_exists(self):
        """
        Tests PUT method on user_ivalt to create a new (second) ivalt
        """

        models.Ivalt.objects.create(
            user=self.test_user_obj,
            mobile = encrypt_with_db_secret('+10123456789'),
            active = False,
        )

        url = reverse('user_ivalt')

        data = {
            'mobile': '+10123456789',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(IVALT_SECRET_KEY="abc")
    def test_put_user_ivalt_no_parameters(self):
        """
        Tests PUT method on user_ivalt
        """

        url = reverse('user_ivalt')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def mock_verify_verification_success(self, url=None, json=None, headers=None, timeout=None):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": { "status": True, "message": "Biometric Authentication successfully done.", "details": { "id": 1111, "name": "user_name", "email": "user_email", "country_code": "country_code", "mobile": "user_mobile", "latitude": "latitude", "longitude": "longitude", "imei": "imei", "address": "user_address" }}}
        return mock_response

    def mock_verify_verification_pending(self, url=None, json=None, headers=None, timeout=None):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": { "type": "https://httpstatuses.com/404", "title": "Not Found", "status": 404, "detail": "The mobile number provided (+910123456789) was not found."}}
        return mock_response
    
    def mock_verify_verification_invalid_time_window(self, url=None, json=None, headers=None, timeout=None):
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"error": { "type": "https://httpstatuses.com/403", "title": "Invalid details", "status": 403, "detail": "You are not within the timezone."}}
        return mock_response
    
    def mock_verify_verification_invalid_geo_fance(self, url=None, json=None, headers=None):
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"error": { "type": "https://httpstatuses.com/403", "title": "Invalid details", "status": 403, "detail": "You are not within the geofencing location."}}
        return mock_response

    @override_settings(IVALT_SECRET_KEY="abc")
    @patch('restapi.utils.ivalt.requests.post', mock_verify_verification_success)
    def test_activate_ivalt_verification_success(self):
        """
        Tests POST method on user_ivalt to activate a ivalt
        """
        ivalt = models.Ivalt.objects.create(
            user=self.test_user_obj,
            mobile=encrypt_with_db_secret('+10123456789'),
            active=False,
        )

        url = reverse('user_ivalt')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        print(response.data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        db_ivalt = models.Ivalt.objects.get(pk=ivalt.id)
        self.assertTrue(db_ivalt.active)

    @override_settings(IVALT_SECRET_KEY="abc")
    @patch('restapi.utils.ivalt.requests.post', mock_verify_verification_pending)
    def test_activate_ivalt_verification_pending(self):
        """
        Tests POST method on user_ivalt

        waiting for user's authenication using ivalt mobile app
        
        """
        
        ivalt = models.Ivalt.objects.create(
            user=self.test_user_obj,
            mobile = encrypt_with_db_secret('+10123456789'),
            active = False,
        )

        url = reverse('user_ivalt')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(IVALT_SECRET_KEY="abc")
    @patch('restapi.utils.ivalt.requests.post', mock_verify_verification_invalid_time_window)
    def test_activate_ivalt_verification_failed_invalid_time_window(self):
        """
        Tests POST method on user_ivalt

        waiting for user's authenication using ivalt mobile app
        """

        ivalt = models.Ivalt.objects.create(
            user=self.test_user_obj,
            mobile = encrypt_with_db_secret('+10123456789'),
            active = False,
        )

        url = reverse('user_ivalt')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(IVALT_SECRET_KEY="abc")
    @patch('restapi.utils.ivalt.requests.post', mock_verify_verification_invalid_geo_fance)
    def test_activate_ivalt_verification_failed_invalid_geo_fance(self):
        """
        Tests POST method on user_ivalt

        waiting for user's authenication using ivalt mobile app
        """
        ivalt = models.Ivalt.objects.create(
            user=self.test_user_obj,
            mobile = encrypt_with_db_secret('+10123456789'),
            active = False,
        )

        url = reverse('user_ivalt')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(IVALT_SECRET_KEY="abc")
    def test_post_user_ivalt_not_exist(self):
        """
        Tests POST method on user_ivalt
        """

        url = reverse('user_ivalt')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('non_field_errors')[0], 'NO_PERMISSION_OR_NOT_EXIST')

    @override_settings(IVALT_SECRET_KEY="abc")
    def test_delete_user_ivalt(self):
        """
        Tests DELETE method on user_ivalt
        """

        ivalt = models.Ivalt.objects.create(
            user=self.test_user_obj,
            mobile = encrypt_with_db_secret('+10123456789'),
            active = False,
        )

        url = reverse('user_ivalt')

        data = {
            'ivalt_id': ivalt.id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.data, {
            "ivalt":[]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(IVALT_SECRET_KEY="abc")
    def test_delete_user_ivalt_no_ivalt_id (self):
        """
        Tests DELETE method on user_ivalt with no ivalt_id
        """

        url = reverse('user_ivalt')

        data = {
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(IVALT_SECRET_KEY="abc")
    def test_delete_user_ivalt_ivalt_id_no_uuid(self):
        """
        Tests DELETE method on user_ivalt with ivalt_id not being a uuid
        """

        url = reverse('user_ivalt')

        data = {
            'ivalt_id': '12345'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    @override_settings(IVALT_SECRET_KEY="abc")
    def test_delete_user_ivalt_ivalt_id_not_exist(self):
        """
        Tests DELETE method on user_ivalt with ivalt_id not existing
        """

        url = reverse('user_ivalt')

        data = {
            'ivalt_id': '7e866c32-3e4d-4421-8a7d-3ac62f980fd3'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

