from django.test import TestCase
from socket import gaierror

from ssl import SSLError
from mock import patch
import time
from restapi.utils import duo_auth_check, duo_auth_enroll, duo_auth_enroll_status, duo_auth_auth



class TestDuoAuthCheckUtils(TestCase):

    def mock_check(self):
        return {
            'time': int(time.time())
        }

    def mock_invalid_host(self):
        raise gaierror

    def mock_invalid_cert(self):
        raise SSLError

    def mock_invalid_integration_key(self):
        raise RuntimeError('Invalid integration key')

    def mock_invalid_secret_key(self):
        raise RuntimeError('Invalid signature')

    def mock_other_api_error(self):
        raise RuntimeError('Other API Error')

    def mock_duo_offline(self):
        # raise any irregular exception
        raise Exception

    @patch('duo_client.Auth.check', mock_check)
    def test_duo_auth_check_success(self):
        result = duo_auth_check('integration_key', 'secret_key', 'host')

        self.assertTrue('time' in result)

    @patch('duo_client.Auth.check', mock_invalid_host)
    def test_duo_auth_check_invalid_host(self):
        result = duo_auth_check('integration_key', 'secret_key', 'host')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Host incorrect: Could not be found')

    @patch('duo_client.Auth.check', mock_invalid_cert)
    def test_duo_auth_check_invalid_cert(self):
        result = duo_auth_check('integration_key', 'secret_key', 'host')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Host incorrect: SSL Certificate Error')


    @patch('duo_client.Auth.check', mock_invalid_integration_key)
    def test_duo_auth_check_invalid_integration_key(self):
        result = duo_auth_check('integration_key', 'secret_key', 'host')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Invalid integration key')


    @patch('duo_client.Auth.check', mock_invalid_secret_key)
    def test_duo_auth_check_invalid_secret_key(self):
        result = duo_auth_check('integration_key', 'secret_key', 'host')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Invalid secret key')

    @patch('duo_client.Auth.check', mock_other_api_error)
    def test_duo_auth_check_other_api_error(self):
        result = duo_auth_check('integration_key', 'secret_key', 'host')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Other API Error')

    @patch('duo_client.Auth.check', mock_duo_offline)
    def test_duo_auth_check_duo_offline(self):
        result = duo_auth_check('integration_key', 'secret_key', 'host')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Duo offline. Try again later.')

class TestDuoAuthEnrollUtils(TestCase):

    def mock_enroll(self, username):
        return {
            'time': int(time.time())
        }

    def mock_preauth(self, username):
        return {
            'result': 'enroll'
        }

    def mock_invalid_host(self, username):
        raise gaierror

    def mock_invalid_cert(self, username):
        raise SSLError

    def mock_invalid_integration_key(self, username):
        raise RuntimeError('Invalid integration key')

    def mock_invalid_secret_key(self, username):
        raise RuntimeError('Invalid signature')

    def mock_username_already_exists(self, username):
        raise RuntimeError('username already exists')

    def mock_other_api_error(self, username):
        raise RuntimeError('Other API Error')

    def mock_duo_offline(self, username):
        # raise any irregular exception
        raise Exception

    @patch('duo_client.Auth.enroll', mock_enroll)
    @patch('duo_client.Auth.preauth', mock_preauth)
    def test_duo_auth_check_success(self):
        result = duo_auth_enroll('integration_key', 'secret_key', 'host', 'username')

        self.assertTrue('time' in result)

    @patch('duo_client.Auth.enroll', mock_invalid_host)
    @patch('duo_client.Auth.preauth', mock_preauth)
    def test_duo_auth_enroll_invalid_host(self):
        result = duo_auth_enroll('integration_key', 'secret_key', 'host', 'username')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Host incorrect: Could not be found')

    @patch('duo_client.Auth.enroll', mock_invalid_cert)
    @patch('duo_client.Auth.preauth', mock_preauth)
    def test_duo_auth_enroll_invalid_cert(self):
        result = duo_auth_enroll('integration_key', 'secret_key', 'host', 'username')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Host incorrect: SSL Certificate Error')


    @patch('duo_client.Auth.enroll', mock_invalid_integration_key)
    @patch('duo_client.Auth.preauth', mock_preauth)
    def test_duo_auth_enroll_invalid_integration_key(self):
        result = duo_auth_enroll('integration_key', 'secret_key', 'host', 'username')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Invalid integration key')


    @patch('duo_client.Auth.enroll', mock_invalid_secret_key)
    @patch('duo_client.Auth.preauth', mock_preauth)
    def test_duo_auth_enroll_invalid_secret_key(self):
        result = duo_auth_enroll('integration_key', 'secret_key', 'host', 'username')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Invalid secret key')

    @patch('duo_client.Auth.enroll', mock_username_already_exists)
    @patch('duo_client.Auth.preauth', mock_preauth)
    def test_duo_auth_enroll_username_already_exists(self):
        result = duo_auth_enroll('integration_key', 'secret_key', 'host', 'username')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Username already exists in Duo.')

    @patch('duo_client.Auth.enroll', mock_other_api_error)
    @patch('duo_client.Auth.preauth', mock_preauth)
    def test_duo_auth_enroll_invalid_other_api_error(self):
        result = duo_auth_enroll('integration_key', 'secret_key', 'host', 'username')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Other API Error')

    @patch('duo_client.Auth.enroll', mock_duo_offline)
    @patch('duo_client.Auth.preauth', mock_preauth)
    def test_duo_auth_enroll_invalid_duo_offline(self):
        result = duo_auth_enroll('integration_key', 'secret_key', 'host', 'username')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Duo offline. Try again later.')

class TestDuoAuthEnrollStatusUtils(TestCase):

    def mock_enroll_status(self, user_id, activation_code):
        return 'success'

    def mock_invalid_host(self, user_id, activation_code):
        raise gaierror

    def mock_invalid_cert(self, user_id, activation_code):
        raise SSLError

    def mock_invalid_integration_key(self, user_id, activation_code):
        raise RuntimeError('Invalid integration key')

    def mock_invalid_secret_key(self, user_id, activation_code):
        raise RuntimeError('Invalid signature')

    def mock_other_api_error(self, user_id, activation_code):
        raise RuntimeError('Other API Error')

    def mock_duo_offline(self, user_id, activation_code):
        # raise any irregular exception
        raise Exception

    @patch('duo_client.Auth.enroll_status', mock_enroll_status)
    def test_duo_auth_check_success(self):
        result = duo_auth_enroll_status('integration_key', 'secret_key', 'host', 'user_id', 'activation_code')
        self.assertEqual(result, 'success')

    @patch('duo_client.Auth.enroll_status', mock_invalid_host)
    def test_duo_auth_enroll_status_invalid_host(self):
        result = duo_auth_enroll_status('integration_key', 'secret_key', 'host', 'user_id', 'activation_code')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Host incorrect: Could not be found')

    @patch('duo_client.Auth.enroll_status', mock_invalid_cert)
    def test_duo_auth_enroll_status_invalid_cert(self):
        result = duo_auth_enroll_status('integration_key', 'secret_key', 'host', 'user_id', 'activation_code')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Host incorrect: SSL Certificate Error')


    @patch('duo_client.Auth.enroll_status', mock_invalid_integration_key)
    def test_duo_auth_enroll_status_invalid_integration_key(self):
        result = duo_auth_enroll_status('integration_key', 'secret_key', 'host', 'user_id', 'activation_code')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Invalid integration key')


    @patch('duo_client.Auth.enroll_status', mock_invalid_secret_key)
    def test_duo_auth_enroll_status_invalid_secret_key(self):
        result = duo_auth_enroll_status('integration_key', 'secret_key', 'host', 'user_id', 'activation_code')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Invalid secret key')


    @patch('duo_client.Auth.enroll_status', mock_other_api_error)
    def test_duo_auth_enroll_status_other_api_error(self):
        result = duo_auth_enroll_status('integration_key', 'secret_key', 'host', 'user_id', 'activation_code')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Other API Error')


    @patch('duo_client.Auth.enroll_status', mock_duo_offline)
    def test_duo_auth_enroll_status_duo_offline(self):
        result = duo_auth_enroll_status('integration_key', 'secret_key', 'host', 'user_id', 'activation_code')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Duo offline. Try again later.')


class TestDuoAuthAuthUtils(TestCase):

    def mock_auth(self, username, factor, device, pushinfo, passcode, async_txn):
        return {
            # Something
        }

    def mock_invalid_host(self, username, factor, device, pushinfo, passcode, async_txn):
        raise gaierror

    def mock_invalid_cert(self, username, factor, device, pushinfo, passcode, async_txn):
        raise SSLError

    def mock_invalid_integration_key(self, username, factor, device, pushinfo, passcode, async_txn):
        raise RuntimeError('Invalid integration key')

    def mock_invalid_secret_key(self, username, factor, device, pushinfo, passcode, async_txn):
        raise RuntimeError('Invalid signature')

    def mock_other_api_error(self, username, factor, device, pushinfo, passcode, async_txn):
        raise RuntimeError('Other API Error')

    def mock_duo_offline(self, username, factor, device, pushinfo, passcode, async_txn):
        # raise any irregular exception
        raise Exception

    @patch('duo_client.Auth.auth', mock_auth)
    def test_duo_auth_check_success(self):
        result = duo_auth_auth('integration_key', 'secret_key', 'host', 'username', 'factor', 'device')
        self.assertTrue(isinstance(result, dict) and 'error' not in result)

    @patch('duo_client.Auth.auth', mock_invalid_host)
    def test_duo_auth_auth_invalid_host(self):
        result = duo_auth_auth('integration_key', 'secret_key', 'host', 'username', 'factor', 'device')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Host incorrect: Could not be found')

    @patch('duo_client.Auth.auth', mock_invalid_cert)
    def test_duo_auth_auth_invalid_cert(self):
        result = duo_auth_auth('integration_key', 'secret_key', 'host', 'username', 'factor', 'device')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Host incorrect: SSL Certificate Error')


    @patch('duo_client.Auth.auth', mock_invalid_integration_key)
    def test_duo_auth_auth_invalid_integration_key(self):
        result = duo_auth_auth('integration_key', 'secret_key', 'host', 'username', 'factor', 'device')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Invalid integration key')


    @patch('duo_client.Auth.auth', mock_invalid_secret_key)
    def test_duo_auth_auth_invalid_secret_key(self):
        result = duo_auth_auth('integration_key', 'secret_key', 'host', 'username', 'factor', 'device')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Invalid secret key')


    @patch('duo_client.Auth.auth', mock_other_api_error)
    def test_duo_auth_auth_other_api_error(self):
        result = duo_auth_auth('integration_key', 'secret_key', 'host', 'username', 'factor', 'device')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Other API Error')


    @patch('duo_client.Auth.auth', mock_duo_offline)
    def test_duo_auth_auth_duo_offline(self):
        result = duo_auth_auth('integration_key', 'secret_key', 'host', 'username', 'factor', 'device')
        self.assertTrue('error' in result)
        self.assertEqual(result['error'], 'Duo offline. Try again later.')

