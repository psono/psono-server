from django.urls import reverse
from django.conf import settings
from django.utils import timezone
from django.forms.models import model_to_dict
from django.test.utils import override_settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status
from ..authentication import TokenAuthentication

from .base import APITestCaseExtended

from hashlib import sha512
from mock import patch

import binascii
import os
import json

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box

from restapi import models



class AuthenticationTests(APITestCaseExtended):


    def setUp(self):
        pass


    def test_user_token_to_token_hash(self):
        token = '1234'
        self.assertEqual(TokenAuthentication.user_token_to_token_hash(token), sha512(token.encode()).hexdigest() )



    def test_get_token_hash_success_full(self):

        class Object(object):
            pass

        request = Object()

        request.META = {
            'HTTP_AUTHORIZATION': b'token 1234'
        }

        self.assertEqual(TokenAuthentication.get_token_hash(request), 'd404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db')

    def test_get_token_hash_success_error(self):

        class Object(object):
            pass

        request = Object()

        request.META = {
            'HTTP_AUTHORIZATION': b'123'
        }

        try:
            TokenAuthentication.get_token_hash(request)
            self.assertTrue(False, 'get_token_hash should throw an error, so this should not be reached')
        except:
            pass

    def test_get_token_hash_success_error_no_token_hash(self):

        class Object(object):
            pass

        request = Object()

        request.META = {
            'HTTP_AUTHORIZATION': b'Token '
        }
        try:
            TokenAuthentication.get_token_hash(request)
            self.assertTrue(False, 'get_token_hash should throw an error, so this should not be reached')
        except AuthenticationFailed:
            pass

    def test_get_token_hash_success_error_too_many_spaces(self):

        class Object(object):
            pass

        request = Object()

        request.META = {
            'HTTP_AUTHORIZATION': b'Token 1234 56'
        }
        try:
            TokenAuthentication.get_token_hash(request)
            self.assertTrue(False, 'get_token_hash should throw an error, so this should not be reached')
        except AuthenticationFailed:
            pass


class AuthenticateTests(APITestCaseExtended):

    @override_settings(PASSWORD_HASHERS=('restapi.tests.base.InsecureUnittestPasswordHasher',))
    def setUp(self):


        self.session_secret_key = "a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"


        # our public / private key box
        box = PrivateKey.generate()

        self.test_email = "test@example.com"
        self.test_username = "test6@" + settings.ALLOWED_DOMAINS[0]
        self.test_authkey = '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678'
        self.test_public_key = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.test_real_private_key = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '0865977160de11fe18806e6843bc14663433982fdeadc45c217d6127f260ff33'
        self.device_fingerprint = '123456'
        self.device_time = timezone.now()


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
        self.user_obj.save()


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

        # our public / private key box
        box = PrivateKey.generate()

        # our hex encoded public / private keys
        user_session_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        user_session_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        server_crypto_box = Box(PrivateKey(user_session_private_key_hex, encoder=nacl.encoding.HexEncoder),
                                PublicKey(settings.PUBLIC_KEY, encoder=nacl.encoding.HexEncoder))

        login_info_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = server_crypto_box.encrypt(json.dumps({
            'username': self.test_username,
            'authkey': self.test_authkey,
            'device_fingerprint': self.device_fingerprint,
            'device_time': str(self.device_time),
        }).encode("utf-8"), login_info_nonce)
        login_info_encrypted = encrypted[len(login_info_nonce):]

        data = {
            'login_info': nacl.encoding.HexEncoder.encode(login_info_encrypted).decode(),
            'login_info_nonce': nacl.encoding.HexEncoder.encode(login_info_nonce).decode(),
            'public_key': user_session_public_key_hex,
        }

        url = reverse('authentication_login')
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        request_data = json.loads(server_crypto_box.decrypt(
            nacl.encoding.HexEncoder.decode(response.data.get('login_info').decode()),
            nacl.encoding.HexEncoder.decode(response.data.get('login_info_nonce').decode())
        ).decode())

        self.token_key = request_data.get('token', False)

        server_public_key_hex = request_data.get('session_public_key', False)

        # lets encrypt our token
        user_private_key = PrivateKey(self.test_real_private_key,
                          encoder=nacl.encoding.HexEncoder)
        user_session_private_key = PrivateKey(user_session_private_key_hex,
                          encoder=nacl.encoding.HexEncoder)
        server_public_key = PublicKey(server_public_key_hex,
                        encoder=nacl.encoding.HexEncoder)

        # create both our crypto boxes
        user_crypto_box = Box(user_private_key, server_public_key)
        session_crypto_box = Box(user_session_private_key, server_public_key)

        # decrypt session secret
        session_secret_key_nonce_hex = request_data.get('session_secret_key_nonce', False)
        session_secret_key_nonce = nacl.encoding.HexEncoder.decode(session_secret_key_nonce_hex)
        session_secret_key_hex = request_data.get('session_secret_key', False)
        session_secret_key = nacl.encoding.HexEncoder.decode(session_secret_key_hex)
        decrypted_session_key_hex = session_crypto_box.decrypt(session_secret_key, session_secret_key_nonce)

        # decrypt user validator
        user_validator_nonce_hex = request_data.get('user_validator_nonce', False)
        user_validator_nonce = nacl.encoding.HexEncoder.decode(user_validator_nonce_hex)
        user_validator_hex = request_data.get('user_validator', False)
        user_validator = nacl.encoding.HexEncoder.decode(user_validator_hex)

        decrypted_user_validator = user_crypto_box.decrypt(user_validator, user_validator_nonce)

        # encrypt user validator with session key
        verification_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        self.verification_nonce_hex = nacl.encoding.HexEncoder.encode(verification_nonce)
        self.decrypted_session_key = nacl.encoding.HexEncoder.decode(decrypted_session_key_hex)
        self.secret_box = nacl.secret.SecretBox(self.decrypted_session_key)
        encrypted = self.secret_box.encrypt(decrypted_user_validator, verification_nonce)
        verification = encrypted[len(verification_nonce):]
        self.verification_hex = nacl.encoding.HexEncoder.encode(verification)


    # def mock_check(self, user_id=None, factor=None, device=None, pushinfo=None, passcode=None, async_txn=False):
    #     return {
    #         'result': 'deny',
    #         'error': 'Funny error'
    #     }

    #@patch('restapi.authentication.TokenAuthentication.get_token_hash', mock_check)
    @override_settings(DEVICE_PROTECTION_DISABLED=True)
    @override_settings(REPLAY_PROTECTION_DISABLED=True)
    def test_authenticate_success(self):

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_authenticate_failure_user_not_active(self):
        """
        Tests that even if a token survives the disabling of a user, a valid token with an inactive user leads to a 401
        """

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        self.assertEqual(models.Token.objects.count(), 1)

        token_backup = model_to_dict(models.Token.objects.first())
        token_backup['user_id'] = str(token_backup['user'])
        del token_backup['user']

        self.user_obj.is_active = False
        self.user_obj.save()

        self.assertEqual(models.Token.objects.count(), 0)

        token_backup = models.Token(**token_backup)
        token_backup.save()

        self.assertEqual(models.Token.objects.count(), 1)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data, {'detail': 'User inactive or deleted.'})


    def test_authenticate_failure_user_email_not_active(self):

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        self.user_obj.is_email_active = False
        self.user_obj.save()

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data, {'detail': 'Account not yet verified.'})


    def test_authenticate_failure_corrupted_authorization_validator(self):

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode()+'5',
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data, {'detail': 'Invalid token header. Not proper encrypted.'})


    @patch('restapi.authentication.settings', DEVICE_PROTECTION_DISABLED=False)
    def test_authenticate_device_protection_failure_request_device_fingerprint_missing(self, settings_fct):

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data, {'detail': 'Device Fingerprint Protection: request_device_fingerprint missing'})


    @patch('restapi.authentication.settings', DEVICE_PROTECTION_DISABLED=False)
    def test_authenticate_device_protection_failure_request_device_fingerprint_missmatch(self, settings_fct):

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({'request_device_fingerprint': '1234'}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data, {'detail': 'Device Fingerprint Protection: device_fingerprint mismatch'})


    @patch('restapi.authentication.settings', DEVICE_PROTECTION_DISABLED=False, AUTO_PROLONGATION_TOKEN_TIME_VALID=0)
    def test_authenticate_device_protection_success_legacy_variable(self, settings_fct):
        """
        Tests that the legacy "request_device_fingerprint" still works
        """
        models.Token.objects.all().update(device_fingerprint="123456")

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({'request_device_fingerprint': '123456'}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    @patch('restapi.authentication.settings', DEVICE_PROTECTION_DISABLED=False, AUTO_PROLONGATION_TOKEN_TIME_VALID=0)
    def test_authenticate_device_protection_success(self, settings_fct):

        models.Token.objects.all().update(device_fingerprint="123456")

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({'request_device_session': '123456'}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    @patch('restapi.authentication.settings', REPLAY_PROTECTION_DISABLED=False, REPLAY_PROTECTION_TIME_DFFERENCE=20)
    def test_authenticate_replay_protection_failure_request_time_missing(self, settings_fct):

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data, {'detail': 'Replay Protection: request_time missing'})


    @patch('restapi.authentication.settings', REPLAY_PROTECTION_DISABLED=False, REPLAY_PROTECTION_TIME_DFFERENCE=20)
    def test_authenticate_replay_protection_failure_request_time_too_old(self, settings_fct):

        models.Token.objects.all().update(
            client_date=timezone.now(),
            create_date=timezone.now(),
        )

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({'request_time': "2000-01-01T10:00:00.000Z"}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data, {'detail': 'Replay Protection: Time difference too big'})


    @patch('restapi.authentication.settings', REPLAY_PROTECTION_DISABLED=False, REPLAY_PROTECTION_TIME_DFFERENCE=20, AUTO_PROLONGATION_TOKEN_TIME_VALID=0)
    def test_authenticate_replay_protection_success(self, settings_fct):

        models.Token.objects.all().update(
            client_date=timezone.now(),
            create_date=timezone.now(),
        )

        # encrypt authorization validator with session key
        authorization_validator_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        authorization_validator_nonce_hex = nacl.encoding.HexEncoder.encode(authorization_validator_nonce)
        encrypted = self.secret_box.encrypt(json.dumps({'request_time': timezone.now().isoformat()}).encode("utf-8"), authorization_validator_nonce)
        authorization_validator = encrypted[len(authorization_validator_nonce):]
        authorization_validator_hex = nacl.encoding.HexEncoder.encode(authorization_validator)

        url = reverse('authentication_activate_token')

        data = {
            'token': self.token_key,
            'verification': self.verification_hex.decode(),
            'verification_nonce': self.verification_nonce_hex.decode(),
        }

        self.client.credentials(
            HTTP_AUTHORIZATION='Token ' + self.token_key,
            HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
                'text': authorization_validator_hex.decode(),
                'nonce': authorization_validator_nonce_hex.decode(),
            })
        )
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

