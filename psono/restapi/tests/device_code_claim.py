from django.urls import reverse
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from rest_framework import status
import nacl.secret
import nacl.utils
import nacl.encoding
from unittest.mock import patch

from .base import APITestCaseExtended
from restapi import models
from nacl.public import PrivateKey, PublicKey, Box


class ClaimDeviceCodeTest(APITestCaseExtended):
    """
    Test claiming a device code (PUT) via DeviceCodeClaimView
    and validation of ActivateDeviceCodeSerializer.
    """

    def setUp(self):
        # User 1 (primary test user)
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_username = "test@psono.pw"
        self.test_password = "myPassword"
        self.test_authkey = nacl.encoding.HexEncoder.encode(nacl.utils.random(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        
        self.user1_private_key = PrivateKey.generate()
        self.user1_public_key = self.user1_private_key.public_key
        self.test_public_key_hex = self.user1_public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.test_private_key_hex = self.user1_private_key.encode(encoder=nacl.encoding.HexEncoder).decode()


        self.test_secret_key_hex = nacl.encoding.HexEncoder.encode(nacl.utils.random(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce_hex = nacl.encoding.HexEncoder.encode(nacl.utils.random(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_private_key_nonce_hex = nacl.encoding.HexEncoder.encode(nacl.utils.random(settings.NONCE_LENGTH_BYTES)).decode()


        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey=self.test_authkey,
            public_key=self.test_public_key_hex,
            private_key=self.test_private_key_hex, # In reality, this would be encrypted
            private_key_nonce=self.test_private_key_nonce_hex,
            secret_key=self.test_secret_key_hex, # In reality, this would be encrypted
            secret_key_nonce=self.test_secret_key_nonce_hex,
            user_sauce=nacl.encoding.HexEncoder.encode(nacl.utils.random(32)).decode(),
            is_email_active=True
        )

        # User 2 (other user)
        self.other_email = "other@example.com"
        self.other_email_bcrypt = "b"
        self.other_username = "other@psono.pw"
        self.other_authkey = nacl.encoding.HexEncoder.encode(nacl.utils.random(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        
        self.user2_private_key = PrivateKey.generate()
        self.user2_public_key = self.user2_private_key.public_key
        self.other_public_key_hex = self.user2_public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.other_private_key_hex = self.user2_private_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        self.other_secret_key_hex = nacl.encoding.HexEncoder.encode(nacl.utils.random(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.other_secret_key_nonce_hex = nacl.encoding.HexEncoder.encode(nacl.utils.random(settings.NONCE_LENGTH_BYTES)).decode()
        self.other_private_key_nonce_hex = nacl.encoding.HexEncoder.encode(nacl.utils.random(settings.NONCE_LENGTH_BYTES)).decode()

        self.other_user_obj = models.User.objects.create(
            email=self.other_email,
            email_bcrypt=self.other_email_bcrypt,
            username=self.other_username,
            authkey=self.other_authkey,
            public_key=self.other_public_key_hex,
            private_key=self.other_private_key_hex,
            private_key_nonce=self.other_private_key_nonce_hex,
            secret_key=self.other_secret_key_hex,
            secret_key_nonce=self.other_secret_key_nonce_hex,
            user_sauce=nacl.encoding.HexEncoder.encode(nacl.utils.random(32)).decode(),
            is_email_active=True
        )

        # Device Codes
        self.dc_server_private_key = PrivateKey.generate()
        self.dc_server_public_key_hex = self.dc_server_private_key.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
        
        self.dc_user_private_key_for_pending = PrivateKey.generate() # Simulating device's key
        self.dc_user_public_key_for_pending_hex = self.dc_user_private_key_for_pending.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        # Define a default validity for tests if settings don't provide it
        default_validity_minutes = 5 

        self.pending_device_code = models.DeviceCode.objects.create(
            device_fingerprint="pending_device_123",
            device_date=timezone.now(),
            user_public_key=self.dc_user_public_key_for_pending_hex, # Key of the device initiating the flow
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key.encode(encoder=nacl.encoding.HexEncoder).decode(),
            state=models.DeviceCode.DeviceCodeState.PENDING,
            valid_till=timezone.now() + timedelta(minutes=default_validity_minutes)
        )

        self.active_device_code = models.DeviceCode.objects.create(
            device_fingerprint="active_device_456",
            device_date=timezone.now(),
            user=self.test_user_obj, # Associated with test_user_obj
            user_public_key=self.test_public_key_hex, # Associated with test_user_obj's actual public key
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key.encode(encoder=nacl.encoding.HexEncoder).decode(),
            state=models.DeviceCode.DeviceCodeState.CLAIMED,
            encrypted_credentials=b"already_encrypted_data",
            encrypted_credentials_nonce=nacl.encoding.HexEncoder.encode(nacl.utils.random(settings.NONCE_LENGTH_BYTES)).decode()[:64],
            valid_till=timezone.now() + timedelta(minutes=default_validity_minutes)
        )

        self.expired_device_code = models.DeviceCode.objects.create(
            device_fingerprint="expired_device_789",
            device_date=timezone.now(),
            user_public_key=self.dc_user_public_key_for_pending_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key.encode(encoder=nacl.encoding.HexEncoder).decode(),
            state=models.DeviceCode.DeviceCodeState.PENDING, # Will be PENDING initially
            valid_till=timezone.now() - timedelta(minutes=1) # Expired
        )
        
        # This one we will make expire by advancing time with mock
        self.pending_device_code_will_expire = models.DeviceCode.objects.create(
            device_fingerprint="pending_expire_device_000",
            device_date=timezone.now(),
            user_public_key=self.dc_user_public_key_for_pending_hex,
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key.encode(encoder=nacl.encoding.HexEncoder).decode(),
            state=models.DeviceCode.DeviceCodeState.PENDING,
            valid_till=timezone.now() + timedelta(seconds=5) # Expires very soon
        )

        # For mismatch test: This DC expects a claim from a device whose public key is known.
        # The user claiming (test_user_obj) will have a *different* public key.
        # The view's logic `instance.user is not None and instance.user != request.user:` is a bit specific.
        # The serializer sets `instance.user = request.user`.
        # So for this exact path, the instance.user would need to be pre-set by some other means.
        # For now, we will create a DC that is simply PENDING, and the serializer should handle assigning the claiming user.
        # The mismatch test from the view description seems to target a race condition or an already (improperly) assigned user.
        # Let's try to create one that is ALREADY assigned to other_user_obj but somehow PENDING
        self.pending_dc_assigned_other_user = models.DeviceCode.objects.create(
            device_fingerprint="mismatch_pending_device_111",
            device_date=timezone.now(),
            user=self.other_user_obj, # Pre-assigned to other_user_obj
            user_public_key=self.other_public_key_hex, # Key of other_user_obj
            server_public_key=self.dc_server_public_key_hex,
            server_private_key=self.dc_server_private_key.encode(encoder=nacl.encoding.HexEncoder).decode(),
            state=models.DeviceCode.DeviceCodeState.PENDING, # Still PENDING
            valid_till=timezone.now() + timedelta(minutes=default_validity_minutes)
        )


        # Sample valid encrypted data and nonce for payload
        # In a real scenario, client encrypts (e.g. user's session token + API key secrets)
        # using a box with device_private_key and server_public_key from the DeviceCode object
        
        # For testing, we need server's public key from the DC object and device's private key that initiated.
        # Let's assume self.dc_user_private_key_for_pending is the device's private key for self.pending_device_code
        server_pub_key_for_box = PublicKey(self.pending_device_code.server_public_key, encoder=nacl.encoding.HexEncoder)
        
        # Use the device's private key that was used to generate the user_public_key on the DC
        device_priv_key_for_box = self.dc_user_private_key_for_pending

        box = Box(device_priv_key_for_box, server_pub_key_for_box)
        
        self.plain_credentials = b"super_secret_session_token_and_keys"
        self.valid_nonce_bytes = nacl.utils.random(Box.NONCE_SIZE)
        self.valid_nonce_hex = nacl.encoding.HexEncoder.encode(self.valid_nonce_bytes).decode()
        
        encrypted_data_bytes = box.encrypt(self.plain_credentials, self.valid_nonce_bytes)
        self.valid_encrypted_credentials_hex = nacl.encoding.HexEncoder.encode(encrypted_data_bytes.ciphertext).decode()

    def test_claim_device_code_success(self):
        """
        Tests successful claiming of a PENDING device code by an authenticated user.
        """
        url = reverse('device_code_claim', kwargs={'device_code': str(self.pending_device_code.id)})
        payload = {
            'encrypted_credentials_input': self.valid_encrypted_credentials_hex,
            'encrypted_credentials_nonce': self.valid_nonce_hex
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, payload)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Refresh the instance from DB
        self.pending_device_code.refresh_from_db()
        self.assertEqual(self.pending_device_code.state, models.DeviceCode.DeviceCodeState.CLAIMED)
        self.assertEqual(self.pending_device_code.user, self.test_user_obj)
        
        # Verify stored credentials (nonce is hex, credentials should be bytes)
        self.assertIsNotNone(self.pending_device_code.encrypted_credentials)
        self.assertEqual(self.pending_device_code.encrypted_credentials_nonce, self.valid_nonce_hex)
        
        # Check response data (serializer output)
        self.assertEqual(response.data['state'], models.DeviceCode.DeviceCodeState.CLAIMED.value) # Serializer returns value
        self.assertEqual(response.data['user'], self.test_user_obj.id)
        self.assertEqual(response.data['server_public_key'], self.pending_device_code.server_public_key)
        self.assertEqual(response.data['user_public_key'], self.pending_device_code.user_public_key)
        self.assertEqual(response.data['encrypted_credentials_nonce'], self.valid_nonce_hex)
        
        # Validate the encrypted_credentials from response (it's re-encoded to hex by serializer)
        # It should be decryptable by the server (using dc_server_private_key) and the original user device (dc_user_private_key_for_pending)
        response_encrypted_hex = response.data['encrypted_credentials']
        self.assertIsNotNone(response_encrypted_hex)

        # Test decryption using the server's private key and the device's public key
        # This ensures the credentials stored and returned are usable by the server side for potential future use
        # (though in this flow, it's more about client storing it)
        dc_server_priv_key = self.dc_server_private_key
        device_pub_key_for_box = PublicKey(self.pending_device_code.user_public_key, encoder=nacl.encoding.HexEncoder)
        decrypt_box_server_perspective = Box(dc_server_priv_key, device_pub_key_for_box)
        
        try:
            decrypted_by_server = decrypt_box_server_perspective.decrypt(nacl.encoding.HexEncoder.decode(response_encrypted_hex), nacl.encoding.HexEncoder.decode(self.valid_nonce_hex))
            self.assertEqual(decrypted_by_server, self.plain_credentials, "Credentials in response not decryptable by server or content mismatch.")
        except nacl.exceptions.CryptoError:
            self.fail("Failed to decrypt credentials from response using server key context.")

    def test_claim_device_code_unauthenticated(self):
        """
        Tests that an unauthenticated user cannot claim a device code.
        """
        url = reverse('device_code_claim', kwargs={'device_code': str(self.pending_device_code.id)})
        payload = {
            'encrypted_credentials_input': self.valid_encrypted_credentials_hex,
            'encrypted_credentials_nonce': self.valid_nonce_hex
        }

        # No force_authenticate here
        response = self.client.put(url, payload)

        # IsAuthenticated permission usually returns 401 if no auth at all, 
        # or 403 if auth failed/not provided for TokenAuthentication
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_claim_device_code_already_active(self):
        """
        Tests attempting to claim an already ACTIVE device code.
        """
        url = reverse('device_code_claim', kwargs={'device_code': str(self.active_device_code.id)})
        payload = {
            'encrypted_credentials_input': self.valid_encrypted_credentials_hex,
            'encrypted_credentials_nonce': self.valid_nonce_hex
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, payload)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"detail": "DEVICE_CODE_ALREADY_CLAIMED"})
        # Ensure the DC state hasn't changed from ACTIVE
        self.active_device_code.refresh_from_db()
        self.assertEqual(self.active_device_code.state, models.DeviceCode.DeviceCodeState.CLAIMED)

    def test_claim_device_code_already_expired_past_valid_till(self):
        """
        Tests attempting to claim a device code whose valid_till is in the past.
        """
        url = reverse('device_code_claim', kwargs={'device_code': str(self.expired_device_code.id)})
        payload = {
            'encrypted_credentials_input': self.valid_encrypted_credentials_hex,
            'encrypted_credentials_nonce': self.valid_nonce_hex
        }
        
        # Ensure it was PENDING before the call
        self.assertEqual(self.expired_device_code.state, models.DeviceCode.DeviceCodeState.PENDING)

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, payload)


        # Verify the state was updated to EXPIRED in the DB by the view
        self.expired_device_code.refresh_from_db()
        self.assertEqual(self.expired_device_code.state, models.DeviceCode.DeviceCodeState.EXPIRED)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"detail": "DEVICE_CODE_EXPIRED"})

    def test_claim_device_code_becomes_expired_on_attempt(self):
        """
        Tests a PENDING code that expires just before/during the claim attempt.
        Uses mock_now to simulate time passing.
        """
        # Ensure it starts as PENDING and valid_till is in near future
        self.assertEqual(self.pending_device_code_will_expire.state, models.DeviceCode.DeviceCodeState.PENDING)
        self.assertTrue(self.pending_device_code_will_expire.valid_till > timezone.now())

        url = reverse('device_code_claim', kwargs={'device_code': str(self.pending_device_code_will_expire.id)})
        payload = {
            'encrypted_credentials_input': self.valid_encrypted_credentials_hex,
            'encrypted_credentials_nonce': self.valid_nonce_hex
        }

        self.client.force_authenticate(user=self.test_user_obj)
        
        # Simulate time passing so the code is now expired
        future_time = self.pending_device_code_will_expire.valid_till + timedelta(seconds=1)
        
        with patch('django.utils.timezone.now', return_value=future_time):
            response = self.client.put(url, payload)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"detail": "DEVICE_CODE_EXPIRED"})
        
        self.pending_device_code_will_expire.refresh_from_db()
        self.assertEqual(self.pending_device_code_will_expire.state, models.DeviceCode.DeviceCodeState.EXPIRED)

    def test_claim_device_code_user_mismatch(self):
        """
        Tests claiming a PENDING code that is unexpectedly already assigned to a different user.
        This tests the `if instance.user is not None and instance.user != request.user:` check.
        """
        # self.pending_dc_assigned_other_user is PENDING but its .user is self.other_user_obj
        url = reverse('device_code_claim', kwargs={'device_code': str(self.pending_dc_assigned_other_user.id)})
        payload = {
            'encrypted_credentials_input': self.valid_encrypted_credentials_hex, # Credentials valid for a generic exchange
            'encrypted_credentials_nonce': self.valid_nonce_hex
        }

        # Authenticate as self.test_user_obj, which is different from self.pending_dc_assigned_other_user.user
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, payload)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"detail": "DEVICE_CODE_USER_MISMATCH"})

        # Ensure the DC state hasn't changed and user remains self.other_user_obj
        self.pending_dc_assigned_other_user.refresh_from_db()
        self.assertEqual(self.pending_dc_assigned_other_user.state, models.DeviceCode.DeviceCodeState.PENDING)
        self.assertEqual(self.pending_dc_assigned_other_user.user, self.other_user_obj)

    def test_claim_serializer_validations(self):
        """
        Tests various validation failures in ActivateDeviceCodeSerializer.
        """
        url = reverse('device_code_claim', kwargs={'device_code': str(self.pending_device_code.id)})
        self.client.force_authenticate(user=self.test_user_obj)

        base_payload = {
            'encrypted_credentials_input': self.valid_encrypted_credentials_hex,
            'encrypted_credentials_nonce': self.valid_nonce_hex
        }

        # Test cases: (field_to_break, broken_value, expected_error_detail_string, expected_error_code)
        # Note: ClaimDeviceCodeSerializer._validate_hex_string uses nacl.encoding.HexEncoder for validation.
        test_cases = [
            # encrypted_credentials_input validations
            ('encrypted_credentials_input', None, "This field is required.", 'required'),
            ('encrypted_credentials_input', '', "This field may not be blank.", 'blank'),
            ('encrypted_credentials_input', '123', "INVALID_HEX_STRING", 'invalid'),
            ('encrypted_credentials_input', 'XXYYZZ', "INVALID_HEX_STRING", 'invalid'),
            
            # encrypted_credentials_nonce validations
            ('encrypted_credentials_nonce', None, "This field is required.", 'required'),
            ('encrypted_credentials_nonce', '', "This field may not be blank.", 'blank'),
            ('encrypted_credentials_nonce', '123', "INVALID_HEX_STRING", 'invalid'),
            ('encrypted_credentials_nonce', 'XXYYZZ', "INVALID_HEX_STRING", 'invalid'),
            ('encrypted_credentials_nonce', 'a' * 65, "Ensure this field has no more than 64 characters.", 'max_length'),
        ]

        initial_dc_state = self.pending_device_code.state
        initial_dc_user = self.pending_device_code.user

        for field, value, err_string, err_code in test_cases:
            with self.subTest(field=field, value=value, error_string=err_string):
                payload = base_payload.copy()
                if value is None: # DRF handles None differently for required fields
                    payload.pop(field)
                else:
                    payload[field] = value
                
                response = self.client.put(url, payload)
                
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, f"Failed for {field}={value}. Response: {response.data}")
                self.assertIn(field, response.data, f"Field {field} not in error response for value {value}. Response: {response.data}")
                
                # We expect a list of ErrorDetail objects
                self.assertIsInstance(response.data[field], list)
                self.assertGreater(len(response.data[field]), 0)
                error_detail = response.data[field][0]
                self.assertEqual(str(error_detail), err_string) # Compare string representation
                self.assertEqual(error_detail.code, err_code)

                # Ensure DeviceCode was not modified
                self.pending_device_code.refresh_from_db()
                self.assertEqual(self.pending_device_code.state, initial_dc_state)
                self.assertEqual(self.pending_device_code.user, initial_dc_user)

    def test_http_method_not_allowed(self):
        """
        Tests that methods other than PUT and OPTIONS are not allowed.
        """
        url = reverse('device_code_claim', kwargs={'device_code': str(self.pending_device_code.id)})
        self.client.force_authenticate(user=self.test_user_obj)

        # Test GET
        response_get = self.client.get(url)
        self.assertEqual(response_get.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(response_get.data, {"detail": "GET method not supported. Use PUT to claim a device code."})

        # Test POST
        response_post = self.client.post(url, {})
        self.assertEqual(response_post.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(response_post.data, {"detail": "POST method not supported. Use PUT to claim a device code."})

        # Test DELETE
        response_delete = self.client.delete(url)
        self.assertEqual(response_delete.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(response_delete.data, {"detail": "DELETE method not supported. Use PUT to claim a device code."})

        # Test PATCH (though not explicitly listed in http_method_names, DRF defaults might catch it)
        response_patch = self.client.patch(url, {})
        self.assertEqual(response_patch.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        # The detail message might vary slightly if PATCH isn't explicitly handled, but 405 is key
        self.assertIn("method not supported", response_patch.data.get("detail", "").lower())