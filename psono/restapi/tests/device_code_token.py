from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
import json
import binascii
import os
from django.conf import settings

from rest_framework import status

import nacl.secret
import nacl.utils
import nacl.encoding
from nacl.public import PrivateKey, PublicKey, Box

from .base import APITestCaseExtended
from restapi import models
from restapi.utils import encrypt_with_db_secret


class PollDeviceCodeTokenTest(APITestCaseExtended):
    """
    Tests for the DeviceCodeTokenView (polling for token).
    """

    def setUp(self):
        # Create users for testing
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_username = "test@psono.pw"
        self.test_authkey = '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678'
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = '33afce78b0152075457e2a4d58b80312162f08ee932551c833b3d08d58574f03'
        
        self.test_user = models.User.objects.create(
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
        
        # Keys for the device that would have initiated the device code flow
        self.device_private_key = PrivateKey.generate()
        self.device_public_key_hex = self.device_private_key.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        # Keys for the server side of the DeviceCode
        self.dc_server_private_key_obj = PrivateKey.generate()
        self.dc_server_public_key_hex = self.dc_server_private_key_obj.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.dc_server_private_key_hex = self.dc_server_private_key_obj.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.dc_server_private_key_hex_encrypted = encrypt_with_db_secret(self.dc_server_private_key_hex)

        # General attributes for DeviceCodes
        self.device_description = "My Test Device Description"
        self.default_validity_minutes = 5

        # 1. PENDING device code
        self.pending_dc = models.DeviceCode.objects.create(
            device_fingerprint="poll_pending_123",
            device_description=self.device_description,
            device_date=timezone.now(),
            user_public_key=self.device_public_key_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key_hex_encrypted,
            state=models.DeviceCode.DeviceCodeState.PENDING,
            valid_till=timezone.now() + timedelta(minutes=self.default_validity_minutes)
        )

        # 2. ACTIVE device code with credentials (for success case)
        self.credentials_plaintext = b"some_secret_token_or_user_data"
        self.credentials_nonce_hex = nacl.encoding.HexEncoder.encode(nacl.utils.random(Box.NONCE_SIZE)).decode()
        self.active_dc_creds_bytes = self.credentials_plaintext
        self.active_dc_with_creds = models.DeviceCode.objects.create(
            device_fingerprint="poll_active_creds_456",
            device_description=self.device_description,
            device_date=timezone.now(),
            user=self.test_user,
            user_public_key=self.device_public_key_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key_hex_encrypted,
            state=models.DeviceCode.DeviceCodeState.CLAIMED,
            encrypted_credentials=self.active_dc_creds_bytes,
            encrypted_credentials_nonce=self.credentials_nonce_hex,
            valid_till=timezone.now() + timedelta(minutes=self.default_validity_minutes)
        )

        # 4. ACTIVE device code with corrupted server_private_key
        self.active_dc_corrupt_key = models.DeviceCode.objects.create(
            device_fingerprint="poll_active_corrupt_key_000",
            device_description=self.device_description,
            device_date=timezone.now(),
            user=self.test_user,
            user_public_key=self.device_public_key_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key="invalidhexstring123",
            state=models.DeviceCode.DeviceCodeState.CLAIMED,
            encrypted_credentials=self.active_dc_creds_bytes,
            encrypted_credentials_nonce=self.credentials_nonce_hex,
            valid_till=timezone.now() + timedelta(minutes=self.default_validity_minutes)
        )

        # 5. PENDING device code, already expired
        self.expired_dc_on_setup = models.DeviceCode.objects.create(
            device_fingerprint="poll_expired_setup_111",
            device_description=self.device_description,
            device_date=timezone.now(),
            user_public_key=self.device_public_key_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key_hex_encrypted,
            state=models.DeviceCode.DeviceCodeState.PENDING,
            valid_till=timezone.now() - timedelta(minutes=1)
        )

        # 7. Device code already in FAILED state
        self.failed_dc = models.DeviceCode.objects.create(
            device_fingerprint="poll_failed_333",
            device_description=self.device_description,
            device_date=timezone.now(),
            user_public_key=self.device_public_key_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key_hex_encrypted,
            state=models.DeviceCode.DeviceCodeState.FAILED,
            valid_till=timezone.now() + timedelta(minutes=self.default_validity_minutes)
        )

    def test_poll_device_code_success_boxed_payload(self):
        """
        Tests successfully polling a device code with credentials.
        """
        initial_token_count = models.Token.objects.count()
        url = reverse('device_code_token', kwargs={'device_code': str(self.active_dc_with_creds.id)})
        response = self.client.post(url, {})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('boxed_payload', response.data)
        self.assertIn('nonce', response.data)

        device_original_private_key = self.device_private_key
        dc_server_public_key_from_db = PublicKey(self.active_dc_with_creds.server_public_key, encoder=nacl.encoding.HexEncoder)
        client_box = Box(device_original_private_key, dc_server_public_key_from_db)

        try:
            decrypted_payload = json.loads(client_box.decrypt(nacl.encoding.HexEncoder.decode(response.data['boxed_payload']), nacl.encoding.HexEncoder.decode(response.data['nonce'])))
        except Exception as e:
            self.fail(f"Failed to decrypt payload: {e}")

        self.assertEqual(decrypted_payload['state'], models.DeviceCode.DeviceCodeState.CLAIMED.value)
        self.assertIn('token', decrypted_payload)
        expected_credentials_hex = nacl.encoding.HexEncoder.encode(self.active_dc_with_creds.encrypted_credentials).decode()
        self.assertEqual(decrypted_payload['encrypted_credentials'], expected_credentials_hex)

        self.assertEqual(models.Token.objects.count(), initial_token_count + 1)
        self.assertFalse(models.DeviceCode.objects.filter(id=self.active_dc_with_creds.id).exists())

    def test_http_method_not_allowed_for_poll(self):
        """
        Tests that methods other than POST are not allowed.
        """
        url = reverse('device_code_token', kwargs={'device_code': str(self.pending_dc.id)})
        self.assertEqual(self.client.get(url).status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(self.client.put(url, {}).status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(self.client.delete(url).status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_poll_with_pending_device_code_fails(self):
        """
        Tests that polling a PENDING code returns a proper validation error.
        """
        url = reverse('device_code_token', kwargs={'device_code': str(self.pending_dc.id)})
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
        self.assertEqual(response.data['non_field_errors'][0].code, 'invalid')
        # Verify the error message is DEVICE_CODE_NOT_CLAIMED
        error_message = str(response.data['non_field_errors'][0])
        self.assertIn('DEVICE_CODE_NOT_CLAIMED', error_message)

    def test_poll_with_failed_device_code_fails(self):
        """
        Tests that polling a FAILED code returns DEVICE_CODE_INVALID_STATE error.
        """
        url = reverse('device_code_token', kwargs={'device_code': str(self.failed_dc.id)})
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
        self.assertEqual(response.data['non_field_errors'][0].code, 'invalid')
        # Verify the error message is DEVICE_CODE_INVALID_STATE
        error_message = str(response.data['non_field_errors'][0])
        self.assertIn('DEVICE_CODE_INVALID_STATE', error_message)

    def test_poll_with_expired_device_code_fails(self):
        """
        Tests that polling an expired device code returns a 400 Bad Request.
        """
        url = reverse('device_code_token', kwargs={'device_code': str(self.expired_dc_on_setup.id)})
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
        self.assertEqual(response.data['non_field_errors'][0].code, 'invalid')

    def test_poll_claimed_dc_without_user_fails(self):
        """
        Tests that polling a CLAIMED code without a user returns a data integrity error.
        This should never happen in normal operation - a CLAIMED code must have a user.
        The serializer marks it as FAILED to prevent further issues.
        """
        dc_no_user = models.DeviceCode.objects.create(
            device_fingerprint="claimed_no_user_test",
            state=models.DeviceCode.DeviceCodeState.CLAIMED,
            user_public_key=self.device_public_key_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key_hex_encrypted,
            valid_till=timezone.now() + timedelta(minutes=5)
        )
        url = reverse('device_code_token', kwargs={'device_code': str(dc_no_user.id)})
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
        self.assertEqual(response.data['non_field_errors'][0].code, 'invalid')
        # Verify the error message is DEVICE_CODE_INVALID_STATE (data integrity error)
        error_message = str(response.data['non_field_errors'][0])
        self.assertIn('DEVICE_CODE_INVALID_STATE', error_message)
        
        # Verify the device code was marked as FAILED
        dc_no_user.refresh_from_db()
        self.assertEqual(dc_no_user.state, models.DeviceCode.DeviceCodeState.FAILED)

    def test_poll_claimed_dc_with_corrupted_key_fails(self):
        """
        Tests polling a CLAIMED DC with a corrupted key raises a binascii.Error.
        """
        url = reverse('device_code_token', kwargs={'device_code': str(self.active_dc_corrupt_key.id)})
        with self.assertRaises(binascii.Error):
            self.client.post(url, {})

    def test_poll_claimed_dc_without_credentials(self):
        """
        Tests polling a CLAIMED code without credentials returns a valid payload.
        """
        dc_no_creds = models.DeviceCode.objects.create(
            device_fingerprint="claimed_no_creds_test",
            state=models.DeviceCode.DeviceCodeState.CLAIMED,
            user=self.test_user,
            user_public_key=self.device_public_key_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key_hex_encrypted,
            valid_till=timezone.now() + timedelta(minutes=5)
        )
        url = reverse('device_code_token', kwargs={'device_code': str(dc_no_creds.id)})
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        client_box = Box(self.device_private_key, PublicKey(self.dc_server_public_key_hex, encoder=nacl.encoding.HexEncoder))
        decrypted_payload = json.loads(client_box.decrypt(nacl.encoding.HexEncoder.decode(response.data['boxed_payload']), nacl.encoding.HexEncoder.decode(response.data['nonce'])))

        self.assertIsNone(decrypted_payload['encrypted_credentials'])
        self.assertIsNone(decrypted_payload['encrypted_credentials_nonce'])
        self.assertEqual(decrypted_payload['state'], models.DeviceCode.DeviceCodeState.CLAIMED.value)

    def test_poll_pending_dc_without_user_returns_validation_error(self):
        """
        Tests that polling a PENDING code without a user returns proper validation error.
        This specifically tests the bug where user_id is None causing 500 errors.
        """
        dc_pending_no_user = models.DeviceCode.objects.create(
            device_fingerprint="pending_no_user_test",
            device_description=self.device_description,
            device_date=timezone.now(),
            user_public_key=self.device_public_key_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key_hex_encrypted,
            state=models.DeviceCode.DeviceCodeState.PENDING,
            valid_till=timezone.now() + timedelta(minutes=self.default_validity_minutes)
        )
        url = reverse('device_code_token', kwargs={'device_code': str(dc_pending_no_user.id)})
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
        self.assertEqual(response.data['non_field_errors'][0].code, 'invalid')
        # Verify the error message is DEVICE_CODE_NOT_CLAIMED (because state is PENDING)
        error_message = str(response.data['non_field_errors'][0])
        self.assertIn('DEVICE_CODE_NOT_CLAIMED', error_message)

    def test_poll_with_non_existent_uuid_fails(self):
        """
        Tests that polling with a non-existent UUID returns a 400 Bad Request.
        """
        non_existent_uuid = '12345678-1234-5678-1234-567812345678'
        url = reverse('device_code_token', kwargs={'device_code': non_existent_uuid})
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
        self.assertEqual(response.data['non_field_errors'][0].code, 'invalid')

    def test_throttling_is_configured(self):
        """
        Tests that the view has proper throttling configuration.
        """
        from restapi.views.device_code_token import DeviceCodeTokenView
        from rest_framework.throttling import ScopedRateThrottle
        from django.conf import settings
        
        view = DeviceCodeTokenView()
        self.assertEqual(view.throttle_scope, "device_code_token")
        
        # Test that the view gets throttle classes from settings
        throttles = view.get_throttles()
        has_scoped_throttle = any(isinstance(throttle, ScopedRateThrottle) for throttle in throttles)
        self.assertTrue(has_scoped_throttle, "View should have ScopedRateThrottle configured")
        
        # Test that the throttle rate is configured to 500/day
        throttle_rates = settings.REST_FRAMEWORK.get('DEFAULT_THROTTLE_RATES', {})
        device_code_token_rate = throttle_rates.get('device_code_token')
        self.assertEqual(device_code_token_rate, '500/day', 
                        "device_code_token throttle rate should be configured to 500/day")
