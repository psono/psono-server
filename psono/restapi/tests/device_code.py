import binascii
from uuid import uuid4
from django.db import connection

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
            self.assertEqual(
                len(key_bytes),
                expected_size,
                f"{key_name} should be {expected_size} bytes long when decoded, but got {len(key_bytes)} bytes.",
            )
        except binascii.Error as e:
            self.fail(f"{key_name} ('{hex_key_string}') is not a valid hex string: {e}")
        except Exception as e:
            self.fail(f"An unexpected error occurred while validating {key_name}: {e}")

    def _assert_encrypted_hex_key(self, encrypted_hex_key, expected_size, key_name):
        """Helper to assert that an encrypted string contains a valid hex-encoded key of a specific size when decrypted."""
        self.assertIsInstance(
            encrypted_hex_key, str, f"Encrypted {key_name} should be a string."
        )
        try:
            # Decrypt the key using the DB secret
            decrypted_hex_key = decrypt_with_db_secret(encrypted_hex_key)
            key_bytes = binascii.unhexlify(decrypted_hex_key)
            self.assertEqual(
                len(key_bytes),
                expected_size,
                f"Decrypted {key_name} should be {expected_size} bytes long when decoded, but got {len(key_bytes)} bytes.",
            )
        except binascii.Error as e:
            self.fail(f"Decrypted {key_name} is not a valid hex string: {e}")
        except Exception as e:
            self.fail(
                f"An unexpected error occurred while validating encrypted {key_name}: {e}"
            )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    def test_create_device_code_success(self):
        """
        Tests to create a device code successfully
        """
        url = reverse("device_code")

        input_device_fingerprint = "test-device-fingerprint"
        input_device_description = "My Test Device"
        input_device_date = "2024-01-15T10:30:00Z"
        input_user_public_key = (
            "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        )

        data = {
            "device_fingerprint": input_device_fingerprint,
            "device_description": input_device_description,
            "device_date": input_device_date,
            "user_public_key": input_user_public_key,
        }

        response = self.client.post(url, data)

        # Print response data if the test fails for debugging
        if response.status_code != status.HTTP_201_CREATED:
            print(f"Response data: {response.data}")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.DeviceCode.objects.count(), 1)

        # Verify response data structure based on the new correct response
        self.assertRegex(
            response.data["user_code"], r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$"
        )
        self.assertNotIn(response.data["user_code"], response.data["web_client_url"])
        self.assertIn("id", response.data)
        self.assertIn("state", response.data)
        self.assertIn("valid_till", response.data)
        self.assertIn("server_public_key", response.data)

        self.assertIn("web_client_url", response.data)
        self.assertEqual(response.data["web_client_url"], "https://psono.pw")

        # Verify specific values in response.data
        self.assertEqual(response.data["state"], "pending")

        self._assert_valid_hex_key(
            response.data["server_public_key"],
            PublicKey.SIZE,
            "Server public key in response",
        )

        # Verify persisted data in the database
        device_code_obj = models.DeviceCode.objects.first()
        self.assertIsNotNone(device_code_obj)
        self.assertEqual(device_code_obj.user_code, response.data["user_code"])
        self.assertEqual(
            device_code_obj.state, models.DeviceCode.DeviceCodeState.PENDING
        )
        self.assertEqual(device_code_obj.device_fingerprint, input_device_fingerprint)
        self.assertEqual(device_code_obj.device_description, input_device_description)
        self.assertEqual(device_code_obj.user_public_key, input_user_public_key)
        self.assertIsNotNone(device_code_obj.device_date)
        self.assertIsNone(device_code_obj.session_duration)
        self.assertEqual(device_code_obj.client_type, "app")
        self.assertNotIn("session_duration", response.data)

        self._assert_valid_hex_key(
            device_code_obj.server_public_key,
            PublicKey.SIZE,
            "Persisted server public key",
        )
        # Verify that the server_private_key is encrypted and contains a valid key when decrypted
        self._assert_encrypted_hex_key(
            device_code_obj.server_private_key,
            PrivateKey.SIZE,
            "Persisted server private key",
        )

    @override_settings(MAX_APP_TOKEN_TIME_VALID=300)
    def test_requested_session_duration_is_persisted_without_changing_the_response(
        self,
    ):
        for requested in (None, 1, 30 * 24 * 60 * 60, 2147483647):
            with self.subTest(session_duration=requested):
                response = self.client.post(
                    reverse("device_code"),
                    {
                        "device_fingerprint": "test-device-fingerprint",
                        "device_description": "Android Test phone",
                        "device_date": "2024-01-15T10:30:00Z",
                        "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
                        "session_duration": requested,
                    },
                )
                self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                device_code = models.DeviceCode.objects.get(pk=response.data["id"])
                # Keep the request until redemption, rather than clamping it
                # against limits before the approving user is known.
                self.assertEqual(device_code.session_duration, requested)
                self.assertEqual(
                    set(response.data),
                    {
                        "id",
                        "user_code",
                        "state",
                        "valid_till",
                        "server_public_key",
                        "web_client_url",
                    },
                )
                self.assertAlmostEqual(
                    (device_code.valid_till - device_code.create_date).total_seconds(),
                    300,
                    delta=1,
                )

    def test_create_device_code_rejects_invalid_session_durations(self):
        for requested in (0, -1, 1.5, True, "invalid", 2147483648, [3600], {}):
            with self.subTest(session_duration=requested):
                response = self.client.post(
                    reverse("device_code"),
                    {
                        "device_fingerprint": "test-device-fingerprint",
                        "device_description": "Android Test phone",
                        "device_date": "2024-01-15T10:30:00Z",
                        "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
                        "session_duration": requested,
                    },
                )
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertIn("session_duration", response.data)
                self.assertFalse(models.DeviceCode.objects.exists())

    def test_create_device_code_persists_the_initiating_client_type(self):
        for client_type in (
            "app",
            "webclient",
            "firefox_extension",
            "other-client",
            None,
        ):
            with self.subTest(client_type=client_type):
                response = self.client.post(
                    reverse("device_code"),
                    {
                        "device_fingerprint": "test-device-fingerprint",
                        "device_description": "Test device",
                        "device_date": "2024-01-15T10:30:00Z",
                        "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
                        "client_type": client_type,
                    },
                )
                self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                device_code = models.DeviceCode.objects.get(pk=response.data["id"])
                self.assertEqual(device_code.client_type, client_type)
                self.assertNotIn("client_type", response.data)

    def test_create_device_code_rejects_invalid_client_types(self):
        for client_type in ("", "a" * 65, ["app"], {}, True):
            with self.subTest(client_type=client_type):
                response = self.client.post(
                    reverse("device_code"),
                    {
                        "device_fingerprint": "test-device-fingerprint",
                        "device_description": "Test device",
                        "device_date": "2024-01-15T10:30:00Z",
                        "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
                        "client_type": client_type,
                    },
                )
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertIn("client_type", response.data)
                self.assertFalse(models.DeviceCode.objects.exists())

    def test_comparison_code_collision_retry_budget_is_bounded(self):
        from django.db import IntegrityError

        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "Test device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }
        controller = connection.copy(alias="collision-budget-controller")
        collision_ids = []

        def execute(execute, sql, params, many, context):
            if sql.startswith("INSERT") and '"restapi_device_code"' in sql:
                columns = [
                    column.strip().strip('"')
                    for column in sql.split("(", 1)[1].split(")", 1)[0].split(",")
                ]
                competing = list(params)
                identifier = uuid4()
                competing[columns.index("id")] = identifier
                with controller.cursor() as cursor:
                    cursor.execute(sql, competing)
                collision_ids.append(identifier)
            return execute(sql, params, many, context)

        try:
            with connection.execute_wrapper(execute):
                with self.assertRaises(IntegrityError):
                    self.client.post(reverse("device_code"), data)
            self.assertEqual(len(collision_ids), 5)
            self.assertEqual(models.DeviceCode.objects.count(), 5)
        finally:
            with controller.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM restapi_device_code WHERE id = ANY(%s)",
                    [collision_ids],
                )
            controller.close()

    def test_comparison_code_collision_is_retried(self):
        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "Test device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }
        controller = connection.copy(alias="comparison-code-controller")
        collision_id = uuid4()
        inserted = False
        collision_code = None

        def execute(execute, sql, params, many, context):
            nonlocal inserted, collision_code
            if (
                not inserted
                and sql.startswith("INSERT")
                and '"restapi_device_code"' in sql
            ):
                inserted = True
                columns = [
                    column.strip().strip('"')
                    for column in sql.split("(", 1)[1].split(")", 1)[0].split(",")
                ]
                competing = list(params)
                competing[columns.index("id")] = collision_id
                collision_code = competing[columns.index("user_code")]
                # A separate real connection commits a competing code after
                # generation but before this request's INSERT. No randomness,
                # ORM methods, query results, or database errors are mocked.
                with controller.cursor() as cursor:
                    cursor.execute(sql, competing)
            return execute(sql, params, many, context)

        try:
            with connection.execute_wrapper(execute):
                response = self.client.post(reverse("device_code"), data)
            self.assertEqual(response.status_code, 201)
            self.assertNotEqual(response.data["user_code"], collision_code)
            self.assertEqual(models.DeviceCode.objects.count(), 2)
        finally:
            if inserted:
                with controller.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM restapi_device_code WHERE id = %s", [collision_id]
                    )
            controller.close()

    def test_create_device_code_rejects_short_public_key(self):
        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "My Test Device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "1234567890abcdef",
        }
        response = self.client.post(reverse("device_code"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        self.assertEqual(
            response.data,
            {
                "user_public_key": [
                    ErrorDetail(string="INVALID_USER_PUBLIC_KEY", code="invalid")
                ]
            },
        )

    def test_create_device_code_rejects_non_hex_public_key(self):
        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "My Test Device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c6XX",
        }
        response = self.client.post(reverse("device_code"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        self.assertEqual(
            response.data,
            {
                "user_public_key": [
                    ErrorDetail(string="INVALID_USER_PUBLIC_KEY", code="invalid")
                ]
            },
        )

    def test_create_device_code_rejects_31_byte_public_key(self):
        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "My Test Device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c6",
        }
        response = self.client.post(reverse("device_code"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        self.assertEqual(
            response.data,
            {
                "user_public_key": [
                    ErrorDetail(string="INVALID_USER_PUBLIC_KEY", code="invalid")
                ]
            },
        )

    def test_create_device_code_rejects_33_byte_public_key(self):
        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "My Test Device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649AA",
        }
        response = self.client.post(reverse("device_code"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        self.assertEqual(
            response.data,
            {
                "user_public_key": [
                    ErrorDetail(string="INVALID_USER_PUBLIC_KEY", code="invalid")
                ]
            },
        )

    def test_create_device_code_rejects_malformed_date(self):
        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "My Test Device",
            "device_date": "not-a-date",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }
        response = self.client.post(reverse("device_code"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        self.assertEqual(
            response.data,
            {
                "device_date": [
                    ErrorDetail(
                        string="Datetime has wrong format. Use one of these formats instead: YYYY-MM-DDThh:mm[:ss[.uuuuuu]][+HH:MM|-HH:MM|Z].",
                        code="invalid",
                    )
                ]
            },
        )

    def test_create_device_code_rejects_invalid_month(self):
        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "My Test Device",
            "device_date": "2024-13-01T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }
        response = self.client.post(reverse("device_code"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        self.assertEqual(
            response.data,
            {
                "device_date": [
                    ErrorDetail(
                        string="Datetime has wrong format. Use one of these formats instead: YYYY-MM-DDThh:mm[:ss[.uuuuuu]][+HH:MM|-HH:MM|Z].",
                        code="invalid",
                    )
                ]
            },
        )

    def test_create_device_code_missing_device_description(self):
        """
        Tests creation fails with missing device_description
        """
        url = reverse("device_code")

        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)

        # Verify specific error message for missing device_description
        expected_error = {
            "device_description": [
                ErrorDetail(string="This field is required.", code="required")
            ]
        }
        self.assertEqual(response.data, expected_error)

    def test_create_device_code_rejects_short_description(self):
        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "ab",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }
        response = self.client.post(reverse("device_code"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        self.assertEqual(
            response.data,
            {
                "device_description": [
                    ErrorDetail(
                        string="Ensure this field has at least 3 characters.",
                        code="min_length",
                    )
                ]
            },
        )

    def test_create_device_code_rejects_short_fingerprint(self):
        data = {
            "device_fingerprint": "short",
            "device_description": "My Test Device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }
        response = self.client.post(reverse("device_code"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        self.assertEqual(
            response.data,
            {
                "device_fingerprint": [
                    ErrorDetail(
                        string="Ensure this field has at least 22 characters.",
                        code="min_length",
                    )
                ]
            },
        )

    def test_create_device_code_rejects_near_minimum_fingerprint(self):
        data = {
            "device_fingerprint": "also-too-short-fp",
            "device_description": "My Test Device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }
        response = self.client.post(reverse("device_code"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)
        self.assertEqual(
            response.data,
            {
                "device_fingerprint": [
                    ErrorDetail(
                        string="Ensure this field has at least 22 characters.",
                        code="min_length",
                    )
                ]
            },
        )

    def test_create_device_code_missing_user_public_key(self):
        """
        Tests creation fails with missing user_public_key
        """
        url = reverse("device_code")

        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "My Test Device",
            "device_date": "2024-01-15T10:30:00Z",
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)

        # Verify specific error message for missing user_public_key
        expected_error = {
            "user_public_key": [
                ErrorDetail(string="This field is required.", code="required")
            ]
        }
        self.assertEqual(response.data, expected_error)

    def test_create_device_code_missing_device_fingerprint(self):
        """
        Tests to create a device code with missing device_fingerprint
        """
        url = reverse("device_code")

        data = {
            "device_description": "My Test Device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)

        # Verify error message for missing device_fingerprint
        self.assertIn("device_fingerprint", response.data)

    def test_create_device_code_missing_device_date(self):
        """
        Tests to create a device code with missing device_date
        """
        url = reverse("device_code")

        data = {
            "device_fingerprint": "test-device-fingerprint",
            "device_description": "My Test Device",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)

        # Verify error message for missing device_date
        self.assertIn("device_date", response.data)

    def test_create_device_code_empty_device_fingerprint(self):
        """
        Tests to create a device code with empty device_fingerprint
        """
        url = reverse("device_code")

        data = {
            "device_fingerprint": "",
            "device_description": "My Test Device",
            "device_date": "2024-01-15T10:30:00Z",
            "user_public_key": "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.DeviceCode.objects.count(), 0)

        # Verify error message for empty device_fingerprint
        self.assertIn("device_fingerprint", response.data)

    def test_method_not_allowed(self):
        """
        Tests that methods other than POST are not allowed
        """
        url = reverse("device_code")

        # Test GET method
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        # Test PUT method
        response = self.client.put(url, {})
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        # Test DELETE method
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
