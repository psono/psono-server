from django.urls import reverse
from django.conf import settings
from django.test.utils import override_settings
from django.contrib.auth.hashers import check_password
from django.core.mail import EmailMultiAlternatives
from rest_framework import status

from restapi import models
from .base import APITestCaseExtended
from ..utils import decrypt_with_db_secret, get_static_bcrypt_hash_from_email

from mock import patch
import binascii
import random
import string
import os


class RegistrationTests(APITestCaseExtended):
    @override_settings(
        WEB_CLIENT_URL="https://psono.pw",
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",),
    )
    def test_concurrent_username_registration_returns_validation_error(self):
        from uuid import uuid4
        from django.db import connection, transaction

        username = f"concurrent-test@{settings.ALLOWED_DOMAINS[0]}"
        payload = {
            "username": username,
            "email": "concurrent-test@example.com",
            "authkey": os.urandom(settings.AUTH_KEY_LENGTH_BYTES).hex(),
            "public_key": os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).hex(),
            "private_key": os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).hex(),
            "private_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "secret_key": os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).hex(),
            "secret_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "user_sauce": "00" * 32,
        }
        controller = connection.copy(alias="registration-controller")
        collision_id = uuid4()
        inserted = False

        def execute(execute, sql, params, many, context):
            nonlocal inserted
            if not inserted and sql.startswith("INSERT") and '"restapi_user"' in sql:
                columns = [
                    column.strip().strip('"')
                    for column in sql.split("(", 1)[1].split(")", 1)[0].split(",")
                ]
                competing = list(params)
                competing[columns.index("id")] = collision_id
                competing[columns.index("private_key_nonce")] = (
                    "competing-private-" + str(collision_id)
                )
                competing[columns.index("secret_key_nonce")] = (
                    "competing-secret-" + str(collision_id)
                )
                # Commit a real competing registration after validation and
                # before INSERT; let PostgreSQL enforce username uniqueness.
                with controller.cursor() as cursor:
                    cursor.execute(sql, competing)
                inserted = True
            return execute(sql, params, many, context)

        try:
            with transaction.atomic():
                with connection.execute_wrapper(execute):
                    response = self.client.post(
                        reverse("authentication_register"), payload
                    )
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn(
                "REGISTRATION_FAILED_USERNAME_ALREADY_EXISTS", response.data["custom"]
            )
            self.assertEqual(models.User.objects.filter(username=username).count(), 1)
        finally:
            if inserted:
                with controller.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM restapi_user WHERE id = %s", [collision_id]
                    )
            controller.close()

    @override_settings(WEB_CLIENT_URL="")
    def test_missing_web_client_url_creates_no_unactivatable_account(self):
        username = f"missing-client@{settings.ALLOWED_DOMAINS[0]}"
        payload = {
            "username": username,
            "email": "missing-client@example.com",
            "authkey": os.urandom(settings.AUTH_KEY_LENGTH_BYTES).hex(),
            "public_key": os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).hex(),
            "private_key": os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).hex(),
            "private_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "secret_key": os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).hex(),
            "secret_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "user_sauce": "00" * 32,
        }
        response = self.client.post(reverse("authentication_register"), payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("REGISTRATION_HAS_BEEN_DISABLED", response.data["custom"])
        self.assertFalse(models.User.objects.filter(username=username).exists())

    @override_settings(
        WEB_CLIENT_URL="https://psono.pw",
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",),
        EMAIL_BACKEND="anymail.backends.brevo.EmailBackend",
        ANYMAIL={"BREVO_API_KEY": "test-key"},
    )
    def test_unsupported_brevo_feature_removes_unactivated_account(self):
        from anymail.exceptions import AnymailUnsupportedFeature

        username = f"unsupported-mail@{settings.ALLOWED_DOMAINS[0]}"
        payload = {
            "username": username,
            "email": "unsupported-mail@example.com",
            "authkey": os.urandom(settings.AUTH_KEY_LENGTH_BYTES).hex(),
            "public_key": os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).hex(),
            "private_key": os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).hex(),
            "private_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "secret_key": os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).hex(),
            "secret_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "user_sauce": "00" * 32,
        }
        with patch(
            "anymail.backends.brevo.EmailBackend.send_messages",
            side_effect=AnymailUnsupportedFeature("Unsupported mail feature"),
        ):
            with self.assertRaises(AnymailUnsupportedFeature):
                self.client.post(reverse("authentication_register"), payload)
        self.assertFalse(models.User.objects.filter(username=username).exists())

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    def test_duplicate_username_creates_no_additional_account(self):
        username = f"duplicate-test@{settings.ALLOWED_DOMAINS[0]}"
        models.User.objects.create(
            username=username,
            private_key_nonce="existing-private",
            secret_key_nonce="existing-secret",
        )
        payload = {
            "username": username,
            "email": "duplicate-test@example.com",
            "authkey": os.urandom(settings.AUTH_KEY_LENGTH_BYTES).hex(),
            "public_key": os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).hex(),
            "private_key": os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).hex(),
            "private_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "secret_key": os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).hex(),
            "secret_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "user_sauce": "00" * 32,
        }
        response = self.client.post(reverse("authentication_register"), payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("USERNAME_ALREADY_EXISTS", response.data["username"])
        self.assertEqual(models.User.objects.count(), 1)

    @override_settings(
        WEB_CLIENT_URL="https://psono.pw",
        REGISTRATION_EMAIL_FILTER=["allowed.example.com"],
    )
    def test_registration_rejects_email_outside_allowed_domains(self):
        username = f"filtered-test@{settings.ALLOWED_DOMAINS[0]}"
        payload = {
            "username": username,
            "email": "filtered-test@example.com",
            "authkey": os.urandom(settings.AUTH_KEY_LENGTH_BYTES).hex(),
            "public_key": os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).hex(),
            "private_key": os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).hex(),
            "private_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "secret_key": os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).hex(),
            "secret_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "user_sauce": "00" * 32,
        }
        response = self.client.post(reverse("authentication_register"), payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(
            "EMAIL_DOMAIN_NOT_ALLOWED_TO_REGISTER", response.data["non_field_errors"]
        )
        self.assertFalse(models.User.objects.exists())

    @override_settings(
        REGISTRATION_EMAIL_FILTER=["example.com"],
        WEB_CLIENT_URL="https://psono.pw",
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",),
    )
    def test_registration_accepts_email_in_allowed_domain(self):
        username = f"allowed-test@{settings.ALLOWED_DOMAINS[0]}"
        payload = {
            "username": username,
            "email": "allowed-test@example.com",
            "authkey": os.urandom(settings.AUTH_KEY_LENGTH_BYTES).hex(),
            "public_key": os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).hex(),
            "private_key": os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).hex(),
            "private_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "secret_key": os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).hex(),
            "secret_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "user_sauce": "00" * 32,
        }
        response = self.client.post(reverse("authentication_register"), payload)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(models.User.objects.filter(username=username).exists())

    @override_settings(
        WEB_CLIENT_URL="https://psono.pw",
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",),
        EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend",
    )
    def test_smtp_delivery_failure_creates_no_account(self):
        username = f"mail-test-smtp@{settings.ALLOWED_DOMAINS[0]}"
        payload = {
            "username": username,
            "email": "mail-test-smtp@example.com",
            "authkey": os.urandom(settings.AUTH_KEY_LENGTH_BYTES).hex(),
            "public_key": os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).hex(),
            "private_key": os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).hex(),
            "private_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "secret_key": os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).hex(),
            "secret_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "user_sauce": "00" * 32,
        }
        with patch(
            "django.core.mail.backends.smtp.EmailBackend.send_messages",
            side_effect=OSError("SMTP unavailable"),
        ):
            response = self.client.post(reverse("authentication_register"), payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(models.User.objects.filter(username=username).exists())

    @override_settings(
        WEB_CLIENT_URL="https://psono.pw",
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",),
        EMAIL_BACKEND="anymail.backends.brevo.EmailBackend",
        ANYMAIL={"BREVO_API_KEY": "test-key"},
    )
    def test_brevo_delivery_creates_account(self):
        username = f"mail-test-brevo@{settings.ALLOWED_DOMAINS[0]}"
        payload = {
            "username": username,
            "email": "mail-test-brevo@example.com",
            "authkey": os.urandom(settings.AUTH_KEY_LENGTH_BYTES).hex(),
            "public_key": os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).hex(),
            "private_key": os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).hex(),
            "private_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "secret_key": os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).hex(),
            "secret_key_nonce": os.urandom(settings.NONCE_LENGTH_BYTES).hex(),
            "user_sauce": "00" * 32,
        }
        with patch("anymail.backends.brevo.EmailBackend.send_messages", return_value=1):
            response = self.client.post(reverse("authentication_register"), payload)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(models.User.objects.filter(username=username).exists())

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_get_authentication_register(self):
        """
        Tests GET method on authentication_register
        """

        url = reverse("authentication_register")

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_put_authentication_register(self):
        """
        Tests PUT method on authentication_register
        """

        url = reverse("authentication_register")

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_delete_authentication_register(self):
        """
        Tests DELETE method on authentication_register
        """

        url = reverse("authentication_register")

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account(self):
        """
        Ensure we can create a new account object.
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(
            url, data, headers={"ACCEPT_LANGUAGE": "de,en-US;q=0.9,en;q=0.8"}
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.User.objects.count(), 1)

        user = models.User.objects.get()

        email_bcrypt = get_static_bcrypt_hash_from_email(email)

        self.assertEqual(decrypt_with_db_secret(user.email), email)
        self.assertEqual(user.language, "de")
        self.assertEqual(user.email_bcrypt, email_bcrypt)
        self.assertTrue(check_password(authkey, user.authkey))
        self.assertEqual(user.public_key, public_key)
        self.assertEqual(user.private_key, private_key)
        self.assertEqual(user.private_key_nonce, private_key_nonce)
        self.assertEqual(user.secret_key, secret_key)
        self.assertEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertEqual(user.user_sauce, user_sauce)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_email_active)

    @override_settings(WEB_CLIENT_URL="")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_without_webclient_url(self):
        """
        Tries to create an account without webclient url which should fail
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(
            url, data, headers={"ACCEPT_LANGUAGE": "de,en-US;q=0.9,en;q=0.8"}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_custom_hashing_params(self):
        """
        Ensure we can create a new user with custom hashing parameters
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
            "hashing_algorithm": "scrypt",
            "hashing_parameters": {"u": 15, "r": 9, "p": 2, "l": 65},
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.User.objects.count(), 1)

        user = models.User.objects.get()

        self.assertEqual(user.hashing_parameters["u"], 15)
        self.assertEqual(user.hashing_parameters["r"], 9)
        self.assertEqual(user.hashing_parameters["p"], 2)
        self.assertEqual(user.hashing_parameters["l"], 65)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_invalid_hashing_params_u(self):
        """
        Ensure that hashing parameter for u that are too low are declined
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
            "hashing_algorithm": "scrypt",
            "hashing_parameters": {
                "u": 13,  # min is 14
                "r": 9,
                "p": 2,
                "l": 65,
            },
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.User.objects.count(), 0)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_invalid_hashing_params_r(self):
        """
        Ensure that hashing parameter for r that are too low are declined
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
            "hashing_algorithm": "scrypt",
            "hashing_parameters": {
                "u": 15,
                "r": 7,  # min is 8
                "p": 2,
                "l": 65,
            },
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.User.objects.count(), 0)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_invalid_hashing_params_p(self):
        """
        Ensure that hashing parameter for p that are too low are declined
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
            "hashing_algorithm": "scrypt",
            "hashing_parameters": {
                "u": 15,
                "r": 9,
                "p": 0,  # min is 1
                "l": 65,
            },
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.User.objects.count(), 0)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_invalid_hashing_params_l(self):
        """
        Ensure that hashing parameter for l that are too low are declined
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
            "hashing_algorithm": "scrypt",
            "hashing_parameters": {
                "u": 15,
                "r": 9,
                "p": 2,
                "l": 63,  # min is 64
            },
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.User.objects.count(), 0)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_not_same_email(self):
        """
        Ensure we can not create an account with the same email address twice
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "bbd90b581b9c956e9077a8c71f61ecd9bf9355bd1aac3590bd995028ed224ae0"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.User.objects.count(), 1)

        user = models.User.objects.get()

        self.assertEqual(decrypt_with_db_secret(user.email), email)

        data["username"] = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.User.objects.count(), 1)
        self.assertEqual(
            response.data.get("non_field_errors"), ["USER_WITH_EMAIL_ALREADY_EXISTS"]
        )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_no_authoritative_email(self):
        """
        Ensure we can not create an account with an authoritative email address
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = "admin@" + settings.ALLOWED_DOMAINS[0]
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "05aa27037cf893e2a4113ddbe8836e1bf395556669904902643670fbf3841338"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_email_no_email_syntax(self):
        """
        Test to register with a email without email syntax
        """
        url = reverse("authentication_register")

        email = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("email"), ["INVALID_EMAIL_FORMAT"])

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_no_email_syntax(self):
        """
        Test to register with a username without email syntax
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("username"), ["INVALID_USERNAME_FORMAT"])

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_not_in_allowed_domains(self):
        """
        Test to register with a username that is not in allowed domains
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@nugrsiojuhsgd.com"
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("username"),
            ["PROVIDED_DOMAIN_NOT_ALLOWED_FOR_REGISTRATION"],
        )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_with_not_allowed_chars(self):
        """
        Test to register with a username that contains not allowed characters
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "!@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("username"),
            ["USERNAME_VALIDATION_NAME_CONTAINS_INVALID_CHARS"],
        )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_start_with_a_period(self):
        """
        Test to register with a username that starts with a period
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        username = "." + username
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("username"), ["INVALID_USERNAME_FORMAT"])

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_start_with_a_dash(self):
        """
        Test to register with a username that starts with a dash
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        username = "-" + username
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("username"), ["Usernames may not start with a dash."]
        )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_end_with_a_period(self):
        """
        Test to register with a username that ends with a period
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + ".@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("username"), ["INVALID_USERNAME_FORMAT"])

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_not_contain_consecutive_periods(self):
        """
        Test to register with a username that contains consecutive periods
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = "njfgdopnsrgipojr..threhtr@" + settings.ALLOWED_DOMAINS[0]
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("username"), ["INVALID_USERNAME_FORMAT"])

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_not_contain_consecutive_dashes(self):
        """
        Test to register with a username that contains consecutive dashes
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = "njfgdopnsrgipojr--threhtr@" + settings.ALLOWED_DOMAINS[0]
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("username"),
            ["Usernames may not contain consecutive dashes."],
        )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_periods_following_dashes(self):
        """
        Test to register with a username that contains periods following dashes
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = "njfgdopnsrgipojr-.threhtr@" + settings.ALLOWED_DOMAINS[0]
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("username"),
            ["Usernames may not contain dashes followed by periods."],
        )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_dashes_following_periods(self):
        """
        Test to register with a username that contains dashes following periods
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = "njfgdopnsrgipojr.-threhtr@" + settings.ALLOWED_DOMAINS[0]
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("username"),
            ["Usernames may not contain periods followed by dashes."],
        )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_end_with_a_dash(self):
        """
        Test to register with a username that ends with a dash
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "-@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("username"), ["Usernames may not end with a dash."]
        )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_username_with_only_one_chars(self):
        """
        Test to register with a username that only has 1 char
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(1))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("username"),
            ["Usernames may not be shorter than 2 chars."],
        )

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @patch("restapi.views.register.settings", ALLOW_REGISTRATION=False)
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_with_disabled_registration(
        self, patched_allow_registration
    ):
        """
        Ensure we cannot create a new account object while registration is disabled.
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @patch("restapi.views.register.settings", ENFORCE_MATCHING_USERNAME_AND_EMAIL=True)
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_with_enforced_matching_usernanme_and_email(
        self, patched_force_matched_username_and_email
    ):
        """
        Ensure we cannot create a new account object with mismatching username and email if ENFORCE_MATCHING_USERNAME_AND_EMAIL is set
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(WEB_CLIENT_URL="https://psono.pw")
    @patch.object(EmailMultiAlternatives, "send")
    @override_settings(
        PASSWORD_HASHERS=("restapi.tests.base.InsecureUnittestPasswordHasher",)
    )
    def test_create_account_sends_mail(self, mocked_send):
        """
        Ensure a mail is sent if a new account is created
        """
        url = reverse("authentication_register")

        email = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@example.com"
        )
        username = (
            "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            + "@"
            + settings.ALLOWED_DOMAINS[0]
        )
        authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        public_key = binascii.hexlify(
            os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
        ).decode()
        private_key = binascii.hexlify(
            os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)
        ).decode()
        private_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        secret_key = binascii.hexlify(
            os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)
        ).decode()
        secret_key_nonce = binascii.hexlify(
            os.urandom(settings.NONCE_LENGTH_BYTES)
        ).decode()
        user_sauce = "d25e29d812386431ec8f75ce4dce44464b57a9b742e7caeea78c9d984297c8f1"

        data = {
            "username": username,
            "email": email,
            "authkey": authkey,
            "public_key": public_key,
            "private_key": private_key,
            "private_key_nonce": private_key_nonce,
            "secret_key": secret_key,
            "secret_key_nonce": secret_key_nonce,
            "user_sauce": user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        mocked_send.assert_called_once()
