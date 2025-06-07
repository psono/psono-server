import binascii

from django.urls import reverse
from django.test.utils import override_settings

from rest_framework import status
from rest_framework.exceptions import ErrorDetail

from .base import APITestCaseExtended
from restapi import models
from ..utils import decrypt_with_db_secret

from nacl.public import PrivateKey, PublicKey


class CreateDeviceCodeTest(APITestCaseExtended):
    """
    Test to create a device code (POST)
    """
    def setUp(self):
        pass

    def _assert_valid_hex_key(self, hex_key_string, expected_size, key_name):
        """Helper to assert that a string is a valid hex-encoded key of a specific size."""
        self.assertIsInstance(hex_key_string, str, f"{key_name} should be a string.")
        try:
            key_bytes = binascii.unhexlify(hex_key_string)
            self.assertEqual(len(key_bytes), expected_size, 
                             f"{key_name} should be {expected_size} bytes long when decoded, but got {len(key_bytes)} bytes.")
        except binascii.Error as e:
            self.fail(f"{key_name} ('{hex_key_string}') is not a valid hex string: {e}")
        except Exception as e:
            self.fail(f"An unexpected error occurred while validating {key_name}: {e}")

    def _assert_encrypted_hex_key(self, encrypted_hex_key, expected_size, key_name):
        """Helper to assert that an encrypted string contains a valid hex-encoded key of a specific size when decrypted."""
        self.assertIsInstance(encrypted_hex_key, str, f"Encrypted {key_name} should be a string.")
        try:
            # Decrypt the key using the DB secret
            decrypted_hex_key = decrypt_with_db_secret(encrypted_hex_key)
            key_bytes = binascii.unhexlify(decrypted_hex_key)
            self.assertEqual(len(key_bytes), expected_size, 
                             f"Decrypted {key_name} should be {expected_size} bytes long when decoded, but got {len(key_bytes)} bytes.")
        except binascii.Error as e:
            self.fail(f"Decrypted {key_name} is not a valid hex string: {e}")
        except Exception as e:
            self.fail(f"An unexpected error occurred while validating encrypted {key_name}: {e}")

    @override_settings(WEB_CLIENT_URL='https://psono.pw')
    def test_create_device_code_success(self):
        """
        Tests to create a device code successfully
        """
        url = reverse('device_code')

        input_device_fingerprint = 'test-device-fingerprint'
        input_device_description = 'My Test Device'
        input_device_date = '2024-01-15T10:30:00Z'
        input_user_public_key = '5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649'

        data = {
            'device_fingerprint': input_device_fingerprint,
            'device_description': input_device_description,
            'device_date': input_device_date,
            'user_public_key': input_user_public_key
        }

        response = self.client.post(url, data)

        # Print response data if the test fails for debugging
        if response.status_code != status.HTTP_201_CREATED:
            print(f"Response data: {response.data}")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.DeviceCode.objects.count(), 1)
        
        # Verify response data structure based on the new correct response
        self.assertIn('id', response.data)
        self.assertIn('state', response.data)
        self.assertIn('valid_till', response.data)
        self.assertIn('server_public_key', response.data)
        
        self.assertIn('web_client_url', response.data)
        self.assertEqual(response.data['web_client_url'], 'https://psono.pw')

        # Verify specific values in response.data
        self.assertEqual(response.data['state'], 'pending')

        self._assert_valid_hex_key(response.data['server_public_key'], PublicKey.SIZE, "Server public key in response")
        
        # Verify persisted data in the database
        device_code_obj = models.DeviceCode.objects.first()
        self.assertIsNotNone(device_code_obj)
        self.assertEqual(device_code_obj.state, models.DeviceCode.DeviceCodeState.PENDING)
        self.assertEqual(device_code_obj.device_fingerprint, input_device_fingerprint)
        self.assertEqual(device_code_obj.device_description, input_device_description)
        self.assertEqual(device_code_obj.user_public_key, input_user_public_key)
        self.assertIsNotNone(device_code_obj.device_date)
        
        self._assert_valid_hex_key(device_code_obj.server_public_key, PublicKey.SIZE, "Persisted server public key")
        # Verify that the server_private_key is encrypted and contains a valid key when decrypted
        self._assert_encrypted_hex_key(device_code_obj.server_private_key, PrivateKey.SIZE, "Persisted server private key")

    def test_create_device_code_invalid_user_public_key(self):
        """
        Tests that invalid user_public_key formats are rejected.
        """
        url = reverse('device_code')
        input_device_fingerprint = 'test-device-fingerprint'
        input_device_description = 'My Test Device'
        input_device_date = '2024-01-15T10:30:00Z'

        invalid_keys = [
            "1234567890abcdef",  # Too short
            "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c6XX",  # Non-hex characters
            "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c6",  # Wrong length (31 bytes)
            "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649AA",  # Wrong length (33 bytes)
        ]

        initial_count = models.DeviceCode.objects.count()
        expected_error = {'user_public_key': [ErrorDetail(string='INVALID_USER_PUBLIC_KEY', code='invalid')]}

        for invalid_key in invalid_keys:
            with self.subTest(invalid_key=invalid_key):
                data = {
                    'device_fingerprint': input_device_fingerprint,
                    'device_description': input_device_description,
                    'device_date': input_device_date,
                    'user_public_key': invalid_key
                }
                response = self.client.post(url, data)
                
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertEqual(models.DeviceCode.objects.count(), initial_count)
                self.assertEqual(response.data, expected_error)

    def test_create_device_code_invalid_device_date(self):
        """
        Tests that invalid device_date formats are rejected.
        """
        url = reverse('device_code')
        input_device_fingerprint = 'test-device-fingerprint'
        input_device_description = 'My Test Device'
        input_user_public_key = '5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649'

        invalid_dates = [
            "not-a-date",  # Invalid format
            "2024-13-01T10:30:00Z",  # Invalid month
        ]

        initial_count = models.DeviceCode.objects.count()
        expected_error = {'device_date': [ErrorDetail(string='Datetime has wrong format. Use one of these formats instead: YYYY-MM-DDThh:mm[:ss[.uuuuuu]][+HH:MM|-HH:MM|Z].', code='invalid')]}

        for invalid_date in invalid_dates:
            with self.subTest(invalid_date=invalid_date):
                data = {
                    'device_fingerprint': input_device_fingerprint,
                    'device_description': input_device_description,
                    'device_date': invalid_date,
                    'user_public_key': input_user_public_key
                }
                response = self.client.post(url, data)
                
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertEqual(models.DeviceCode.objects.count(), initial_count)
                self.assertEqual(response.data, expected_error)

    def test_create_device_code_missing_device_description(self):
        """
        Tests creation fails with missing device_description
        """
        url = reverse('device_code')

        data = {
            'device_fingerprint': 'test-device-fingerprint',
            'device_date': '2024-01-15T10:30:00Z',
            'user_public_key': '5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649'
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        
        # Verify specific error message for missing device_description
        expected_error = {'device_description': [ErrorDetail(string='This field is required.', code='required')]}
        self.assertEqual(response.data, expected_error)

    def test_create_device_code_invalid_device_description(self):
        """
        Tests that invalid device_description formats are rejected.
        """
        url = reverse('device_code')
        input_device_fingerprint = 'test-device-fingerprint'
        input_device_date = '2024-01-15T10:30:00Z'
        input_user_public_key = '5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649'

        error_detail_min_length = ErrorDetail(string='Ensure this field has at least 3 characters.', code='min_length')

        invalid_descriptions = [
            ("too_short", "ab", error_detail_min_length),
        ]

        initial_count = models.DeviceCode.objects.count()

        for reason, invalid_description, expected_error_detail_obj in invalid_descriptions:
            with self.subTest(reason=reason, invalid_description=invalid_description):
                data = {
                    'device_fingerprint': input_device_fingerprint,
                    'device_description': invalid_description,
                    'device_date': input_device_date,
                    'user_public_key': input_user_public_key
                }
                response = self.client.post(url, data)
                
                expected_error_response_dict = {'device_description': [expected_error_detail_obj]}

                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 
                                 f"Failed for {reason}: status code was {response.status_code}, expected 400. Error: {response.data}")
                self.assertEqual(models.DeviceCode.objects.count(), initial_count, 
                                 f"Failed for {reason}: DeviceCode count changed. Error: {response.data}")
                self.assertEqual(response.data, expected_error_response_dict, 
                                 f"Failed for {reason}: error response was {response.data}, expected {expected_error_response_dict}.")

    def test_create_device_code_invalid_device_fingerprint(self):
        """
        Tests that invalid device_fingerprint formats are rejected.
        """
        url = reverse('device_code')
        input_device_description = 'My Test Device'
        input_device_date = '2024-01-15T10:30:00Z'
        input_user_public_key = '5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649'

        invalid_fingerprints = [
            "short",  # Too short (less than 22 characters)
            "also-too-short-fp",  # Still too short (18 characters)
        ]

        initial_count = models.DeviceCode.objects.count()
        expected_error = {'device_fingerprint': [ErrorDetail(string='Ensure this field has at least 22 characters.', code='min_length')]}

        for invalid_fingerprint in invalid_fingerprints:
            with self.subTest(invalid_fingerprint=invalid_fingerprint):
                data = {
                    'device_fingerprint': invalid_fingerprint,
                    'device_description': input_device_description,
                    'device_date': input_device_date,
                    'user_public_key': input_user_public_key
                }
                response = self.client.post(url, data)
                
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertEqual(models.DeviceCode.objects.count(), initial_count)
                self.assertEqual(response.data, expected_error)

    def test_create_device_code_missing_user_public_key(self):
        """
        Tests creation fails with missing user_public_key
        """
        url = reverse('device_code')

        data = {
            'device_fingerprint': 'test-device-fingerprint',
            'device_description': 'My Test Device',
            'device_date': '2024-01-15T10:30:00Z'
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        
        # Verify specific error message for missing user_public_key
        expected_error = {'user_public_key': [ErrorDetail(string='This field is required.', code='required')]}
        self.assertEqual(response.data, expected_error)

    def test_create_device_code_missing_device_fingerprint(self):
        """
        Tests to create a device code with missing device_fingerprint
        """
        url = reverse('device_code')

        data = {
            'device_description': 'My Test Device',
            'device_date': '2024-01-15T10:30:00Z',
            'user_public_key': '5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649'
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        
        # Verify error message for missing device_fingerprint
        self.assertIn('device_fingerprint', response.data)

    def test_create_device_code_missing_device_date(self):
        """
        Tests to create a device code with missing device_date
        """
        url = reverse('device_code')

        data = {
            'device_fingerprint': 'test-device-fingerprint',
            'device_description': 'My Test Device',
            'user_public_key': '5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649'
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        
        # Verify error message for missing device_date
        self.assertIn('device_date', response.data)

    def test_create_device_code_empty_device_fingerprint(self):
        """
        Tests to create a device code with empty device_fingerprint
        """
        url = reverse('device_code')

        data = {
            'device_fingerprint': '',
            'device_description': 'My Test Device',
            'device_date': '2024-01-15T10:30:00Z',
            'user_public_key': '5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649'
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        
        # Verify error message for empty device_fingerprint
        self.assertIn('device_fingerprint', response.data)

    def test_method_not_allowed(self):
        """
        Tests that methods other than POST are not allowed
        """
        url = reverse('device_code')
        
        # Test GET method
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        
        # Test PUT method
        response = self.client.put(url, {})
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        
        # Test DELETE method
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED) 