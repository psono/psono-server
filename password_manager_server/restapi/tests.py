from django.core.urlresolvers import reverse
from django.core import mail
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from datetime import timedelta
from django.db import IntegrityError

from rest_framework import status
from rest_framework.test import APITestCase, APIClient

import models
from utils import generate_activation_code

import random
import string
import os

from uuid import UUID


class APITestCaseExtended(APITestCase):

    @staticmethod
    def safe_repr(self, obj, short=False):
        _MAX_LENGTH = 80
        try:
            result = repr(obj)
        except Exception:
            result = object.__repr__(obj)
        if not short or len(result) < _MAX_LENGTH:
            return result
        return result[:_MAX_LENGTH] + ' [truncated]...'

    def assertIsUUIDString(self, expr, msg):
        """Check that the expression is a valid uuid"""

        try:
            val = UUID(expr, version=4)
        except ValueError:
            val = False


        if not val:
            msg = self._formatMessage(msg, "%s is not an uuid" % self.safe_repr(expr))
            raise self.failureException(msg)


class SystemTests(APITestCaseExtended):

    def test_smtp_server_running(self):
        import socket
        e = None
        try:
            socket.create_connection((settings.EMAIL_HOST, settings.EMAIL_PORT), None)
        except socket.error as e:
            pass

        self.assertIsNone(e, "SMTP server on %s with port %s is not running. The error returnd was %s" % (settings.EMAIL_HOST, settings.EMAIL_PORT, str(e)))

    def test_send_email(self):
        """
        Try to send a test email
        """

        mail.outbox = []

        successfull_delivered_messages = mail.send_mail('SMTP e-mail test', 'This is a test e-mail message.',
            'info@sanso.pw', ['saschapfeiffer1337@gmail.com'],
            fail_silently=False)

        self.assertEqual(successfull_delivered_messages, 1)

        # Test that one message has been sent.
        self.assertEqual(len(mail.outbox), 1)

        # Verify that the subject of the first message is correct.
        self.assertEqual(mail.outbox[0].subject, 'SMTP e-mail test')

    def test_smtp_credentials(self):

        # TODO write test to check smtp server credentials with SSL / TLS or whatever is configured
        pass

    def test_secret(self):
        secret = settings.SECRET_KEY

        self.assertIsNotNone(secret, 'Please specify a SECRET_KEY that is at least 32 chars long')
        self.assertGreater(len(secret), 0, 'The SECRET_KEY cannot be empty and should have at least 32 chars')
        self.assertGreater(len(secret), 31, 'Please use a minimum of 32 chars for the SECRET_KEY, you only have %s' % (len(secret),))
        self.assertNotEqual(secret, 'SOME SUPER SECRET KEY THAT SHOULD BE RANDOM AND 32 OR MORE DIGITS LONG', 'Please change the SECRET_KEY value')

    def test_activation_link_secret(self):
        secret = settings.ACTIVATION_LINK_SECRET

        self.assertIsNotNone(secret, 'Please specify a ACTIVATION_LINK_SECRET that is at least 32 chars long')
        self.assertGreater(len(secret), 0, 'The ACTIVATION_LINK_SECRET cannot be empty and should have at least 32 chars')
        self.assertGreater(len(secret), 31, 'Please use a minimum of 32 chars for the ACTIVATION_LINK_SECRET, you only have %s' % (len(secret),))
        self.assertNotEqual(secret, 'SOME SUPER SECRET KEY THAT SHOULD BE RANDOM AND 32 OR MORE DIGITS LONG', 'Please change the ACTIVATION_LINK_SECRET value')

    def test_email_from(self):
        secret = settings.EMAIL_FROM

        self.assertIsNotNone(secret, 'Please specify a EMAIL_FROM settings value')
        self.assertGreater(len(secret), 0, 'Please specify a EMAIL_FROM settings value')
        self.assertNotEqual(secret, 'the-mail-for-for-example-useraccount-activations@test.com', 'Please change the EMAIL_FROM value')


class RegistrationTests(APITestCaseExtended):

    def test_create_account(self):
        """
        Ensure we can create a new account object.
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))+ '@sachapfeiffer.com'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

        data = {
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.User.objects.count(), 1)

        user = models.User.objects.get()

        self.assertEqual(user.email, email)
        self.assertTrue(check_password(authkey, user.authkey))
        self.assertEqual(user.public_key, public_key)
        self.assertEqual(user.private_key, private_key)
        self.assertEqual(user.private_key_nonce, private_key_nonce)
        self.assertEqual(user.secret_key, secret_key)
        self.assertEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertEqual(user.user_sauce, user_sauce)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_email_active)


    def test_not_same_email(self):
        """
        Ensure we can not create an account with the same email address twice
        """
        url = reverse('authentication_register')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))+ '@sachapfeiffer.com'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

        data = {
            'email': email,
            'authkey': authkey,
            'public_key': public_key,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(models.User.objects.count(), 1)

        user = models.User.objects.get()

        self.assertEqual(user.email, email)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(models.User.objects.count(), 1)
        self.assertTrue(response.data.get('email', False),
                        'E-Mail in error message does not exist in registration response')



class EmailVerificationTests(APITestCaseExtended):

    def setUp(self):
        self.test_email = u"test@example.com"
        models.User.objects.create(email=self.test_email)

    def test_verify_email(self):
        """
        Ensure we can verify the email
        """
        url = reverse('authentication_verify_email')
        activation_code = generate_activation_code(self.test_email)

        data = {
            'activation_code': activation_code,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user = models.User.objects.filter(email=self.test_email).get()

        self.assertTrue(user.is_email_active)


    def test_verify_email_wrong_code(self):
        """
        Ensure we don't verify emails with wrong codes
        """
        url = reverse('authentication_verify_email')
        activation_code = generate_activation_code(self.test_email+'changedit')

        data = {
            'activation_code': activation_code,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = models.User.objects.filter(email=self.test_email).get()

        self.assertFalse(user.is_email_active)

class LoginTests(APITestCaseExtended):

    def setUp(self):
        self.test_email = u"test@example.com"
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce = os.urandom(32).encode('hex')
        self.user_obj = models.User.objects.create(
            email=self.test_email,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

    def test_unique_constraint_token(self):
        key = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))

        models.Token.objects.create(
            key=key,
            user=self.user_obj
        )

        error_thrown = False

        try:
            models.Token.objects.create(
                key=key,
                user=self.user_obj
            )
        except IntegrityError:
            error_thrown = True

        self.assertTrue(error_thrown,
                        'Unique constraint lifted for Tokens which can lead to security problems')



    def test_login(self):
        """
        Ensure we can login
        """
        url = reverse('authentication_login')

        data = {
            'email': self.test_email,
            'authkey': self.test_authkey,
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data.get('token', False),
                        'Token does not exist in login response')
        self.assertTrue(response.data.get('user', {}).get('id', False),
                        'User ID does not exist in login response')
        self.assertEqual(response.data.get('user', {}).get('public_key', False),
                         self.test_public_key,
                        'Public key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('private_key', False),
                         self.test_private_key,
                        'Private key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('private_key_nonce', False),
                         self.test_private_key_nonce,
                        'Private key nonce is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('secret_key', False),
                         self.test_secret_key,
                        'Secret key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('secret_key_nonce', False),
                         self.test_secret_key_nonce,
                        'Secret key is wrong in response or does not exist')
        self.assertEqual(response.data.get('user', {}).get('user_sauce', False),
                         self.test_user_sauce,
                        'Secret key nonce is wrong in response or does not exist')

        self.assertEqual(models.Token.objects.count(), 1)


    def test_login_with_wrong_password(self):
        """
        Ensure we cannot login with wrong authkey
        """
        url = reverse('authentication_login')

        data = {
            'email': self.test_email,
            'authkey': make_password(os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')),
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.assertEqual(models.Token.objects.count(), 0)


    def test_token_expiration(self):
        """
        Ensure expired tokens are invalid
        """
        url = reverse('authentication_login')

        data = {
            'email': self.test_email,
            'authkey': self.test_authkey,
        }

        models.Token.objects.all().delete()

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data.get('token', False),
                        'Token does not exist in login response')

        token = response.data.get('token', False)

        # to test we first query our datastores with the valid token

        url = reverse('datastore')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # seems to work, so lets now put the token back into the past

        token_obj = models.Token.objects.get()
        time_threshold = timezone.now() - timedelta(seconds=settings.TOKEN_TIME_VALID + 1)

        token_obj.create_date = time_threshold

        token_obj.save()

        # ... and try again

        url = reverse('datastore')

        data = {}

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class LogoutTests(APITestCaseExtended):

    def setUp(self):
        self.test_email = u"test@example.com"
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce = os.urandom(32).encode('hex')
        models.User.objects.create(
            email=self.test_email,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

        url = reverse('authentication_login')

        data = {
            'email': self.test_email,
            'authkey': self.test_authkey,
        }

        response = self.client.post(url, data)

        self.test_token = response.data.get('token', False)

    def test_logout_false_token(self):
        """
        Try to use a fake token
        """

        url = reverse('authentication_logout')


        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token + 'hackIT')
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED,
                         'Any login is accepted')

    def test_logout(self):
        """
        Ensure we can logout
        """

        url = reverse('authentication_logout')


        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK,
                         'Cannot logout with correct credentials')


        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.test_token)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED,
                         'Logout has no real affect, Token not deleted')



class UserModificationTests(APITestCaseExtended):

    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))+ 'test@example.com'
        self.test_authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce = os.urandom(32).encode('hex')
        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))+ 'test@example.com'
        self.test_authkey2 = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        self.test_public_key2 = os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key2 = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        self.test_private_key_nonce2 = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_secret_key2 = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        self.test_secret_key_nonce2 = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        self.test_user_sauce2 = os.urandom(32).encode('hex')
        self.test_user_obj2 = models.User.objects.create(
            email=self.test_email2,
            authkey=make_password(self.test_authkey2),
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

    def reset(self):

        url = reverse('user_update')

        data = {
            'email': self.test_email,
            'authkey': make_password(self.test_authkey),
            'authkey_old': self.test_public_key,
            'private_key': self.test_private_key,
            'private_key_nonce': self.test_private_key_nonce,
            'secret_key': self.test_secret_key,
            'secret_key_nonce': self.test_secret_key_nonce,
            'user_sauce':self.test_user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.client.post(url, data)

    def test_update_user(self):
        """
        Tests to update the user
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))+ 'test@example.com'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        authkey_old = self.test_authkey
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

        data = {
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertEqual(user.email, email)
        self.assertTrue(check_password(authkey, user.authkey))
        self.assertEqual(user.private_key, private_key)
        self.assertEqual(user.private_key_nonce, private_key_nonce)
        self.assertEqual(user.secret_key, secret_key)
        self.assertEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertEqual(user.user_sauce, user_sauce)

        self.reset()

    def test_update_user_with_email_duplicate(self):
        """
        Tests to update the user with an email address that already exists
        """

        url = reverse('user_update')

        email = self.test_email2
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        authkey_old = self.test_authkey
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

        data = {
            'email': email,
            'authkey': authkey,
            'authkey_old': authkey_old,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertNotEqual(user.email, email)
        self.assertFalse(check_password(authkey, user.authkey))
        self.assertNotEqual(user.private_key, private_key)
        self.assertNotEqual(user.private_key_nonce, private_key_nonce)
        self.assertNotEqual(user.secret_key, secret_key)
        self.assertNotEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertNotEqual(user.user_sauce, user_sauce)

        self.reset()

    def test_update_user_missing_old_authkey(self):
        """
        Tests to update the user without the old authentication key
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))+ 'test@example.com'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

        data = {
            'email': email,
            'authkey': authkey,
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertNotEqual(user.email, email)
        self.assertFalse(check_password(authkey, user.authkey))
        self.assertNotEqual(user.private_key, private_key)
        self.assertNotEqual(user.private_key_nonce, private_key_nonce)
        self.assertNotEqual(user.secret_key, secret_key)
        self.assertNotEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertNotEqual(user.user_sauce, user_sauce)

        self.reset()

    def test_update_user_wrong_old_authkey(self):
        """
        Tests to update the user with the wrong old authentication key
        """

        url = reverse('user_update')

        email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))+ 'test@example.com'
        authkey = os.urandom(settings.AUTH_KEY_LENGTH_BYTES).encode('hex')
        private_key = os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES).encode('hex')
        private_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        secret_key = os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES).encode('hex')
        secret_key_nonce = os.urandom(settings.NONCE_LENGTH_BYTES).encode('hex')
        user_sauce = os.urandom(32).encode('hex')

        data = {
            'email': email,
            'authkey': authkey,
            'authkey_old': 'asdf',
            'private_key': private_key,
            'private_key_nonce': private_key_nonce,
            'secret_key': secret_key,
            'secret_key_nonce': secret_key_nonce,
            'user_sauce': user_sauce,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertNotEqual(user.email, email)
        self.assertFalse(check_password(authkey, user.authkey))
        self.assertNotEqual(user.private_key, private_key)
        self.assertNotEqual(user.private_key_nonce, private_key_nonce)
        self.assertNotEqual(user.secret_key, secret_key)
        self.assertNotEqual(user.secret_key_nonce, secret_key_nonce)
        self.assertNotEqual(user.user_sauce, user_sauce)

        self.reset()


class DatastoreTests(APITestCaseExtended):

    def setUp(self):
        self.test_email = u"test@example.com"
        self.test_email2 = u"test2@example.com"
        self.test_password = u"myPassword"
        self.test_authkey = u"c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
                            u"123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
        self.test_public_key = u"5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        self.test_secret_key = u"a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
        self.test_secret_key_enc = u"77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
                                   u"996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
                                   u"571a48eb"
        self.test_secret_key_nonce = u"f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce2 = u"f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = u"d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = u"abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    u"d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    u"a74b9b2452"
        self.test_private_key_nonce = u"4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = u"4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"

        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce = os.urandom(32).encode('hex'),
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce = os.urandom(32).encode('hex'),
            is_email_active=True
        )


    def test_list_datastores_without_credentials(self):
        """
        Tests if someone gets datastores without credentials
        """

        url = reverse('datastore')

        data = {}

        response = self.client.get(url, data, user=self.test_user_obj)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIsInstance(response.data.get('datastores', False), list,
                        'We got some data even with a 401')


    def test_list_datastores(self):
        """
        Tests if the initial listing of datastores works
        """

        url = reverse('datastore')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('datastores', False), list,
                        'Datastores do not exist in list datastores response')
        self.assertEqual(len(response.data.get('datastores', False)), 0,
                        'Datastores hold already data, but should not contain any data at the beginning')

    def test_insert_datastore(self):
        """
        Tests to insert the datastore and check the rights to access it
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': u"my-type",
            'description': u"my-description",
            'data': u"12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('datastore_id', False), False,
                            'Datastore id does not exist in datastore PUT answer')
        self.assertIsUUIDString(str(response.data.get('datastore_id', '')),
                                'Datastore id is no valid UUID')

        new_datastore_id = str(response.data.get('datastore_id'))


        # lets try to get it back in the list

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('datastores', False), list,
                        'Datastores do not exist in list datastores response')
        self.assertGreater(len(response.data.get('datastores', False)), 0,
                        'Datastores hold some data')

        found = False

        for store in response.data.get('datastores', []):
            if store.get('id', '') == new_datastore_id:
                self.assertFalse(found,
                                 'Found our datastore twice in the returned list')
                found = True
                self.assertEqual(store, {
                    'id': new_datastore_id,
                    'type': initial_data['type'],
                    'description': initial_data['description'],
                })

        self.assertTrue(found, 'Did not find the datastore in the datastore list call')

        # lets try to get it back in detail

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {
            'data': initial_data['data'],
            'data_nonce': initial_data['data_nonce'],
            'type': initial_data['type'],
            'description': initial_data['description'],
            'secret_key': initial_data['secret_key'],
            'secret_key_nonce': initial_data['secret_key_nonce'],
        })

        # ok lets try to get the same datastore with a bad user

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # lets also check list view for another user

        url = reverse('datastore')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('datastores', False), list,
                        'Datastores do not exist in list datastores response')

        for store in response.data.get('datastores', []):
            self.assertNotEqual(store.get('id', ''), new_datastore_id,
                                'Found our datastore in the list view of another user')

    def test_insert_datastore_with_same_type_and_description(self):
        """
        Tests to insert the datastore with the same type and description twice
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': u"my-test-type",
            'description': u"my-test-description",
            'data': u"12345",
            'data_nonce': 'a' + ''.join(random.choice(string.ascii_lowercase) for _ in range(63)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': 'b' + ''.join(random.choice(string.ascii_lowercase) for _ in range(63)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('datastore_id', False), False,
                            'Datastore id does not exist in datastore PUT answer')
        self.assertIsUUIDString(str(response.data.get('datastore_id', '')),
                                'Datastore id is no valid UUID')

        initial_data2 = {
            'type': u"my-test-type",
            'description': u"my-test-description",
            'data': u"12345",
            'data_nonce': 'c' + ''.join(random.choice(string.ascii_lowercase) for _ in range(63)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': 'd' + ''.join(random.choice(string.ascii_lowercase) for _ in range(63)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data2)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_datastore(self):
        """
        Tests to update the datastore
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': u"my-sexy-type",
            'description': u"my-sexy-description",
            'data': u"12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('datastore_id', False), False,
                            'Datastore id does not exist in datastore PUT answer')
        self.assertIsUUIDString(str(response.data.get('datastore_id', '')),
                                'Datastore id is no valid UUID')

        new_datastore_id = str(response.data.get('datastore_id'))

        # Initial datastore set, so lets update it

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        updated_data = {
            'data': u"123456",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, updated_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # lets try to get it back in detail

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {
            'type': initial_data['type'],
            'description': initial_data['description'],

            'data': updated_data['data'],
            'data_nonce': updated_data['data_nonce'],
            'secret_key': updated_data['secret_key'],
            'secret_key_nonce': updated_data['secret_key_nonce'],
        })


    def test_change_datastore_type_or_description(self):
        """
        Tests to update the datastore with a type or description which should not work, because its not allwed to change
        those.
        """

        # lets try to create a datastore

        url = reverse('datastore')

        initial_data = {
            'type': u"my-second-sexy-type",
            'description': u"my-second-sexy-description",
            'data': u"12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('datastore_id', False), False,
                            'Datastore id does not exist in datastore PUT answer')
        self.assertIsUUIDString(str(response.data.get('datastore_id', '')),
                                'Datastore id is no valid UUID')

        new_datastore_id = str(response.data.get('datastore_id'))

        # Initial datastore set, so lets update it

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        updated_data = {
            'type': u"my-try-to-change-the-type",
            'description': u"my-try-to-change-the-description",
            'data': u"123456",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'secret_key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'secret_key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, updated_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # lets try to get it back in detail

        url = reverse('datastore', kwargs={'uuid': new_datastore_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {
            'type': initial_data['type'],
            'description': initial_data['description'],

            'data': updated_data['data'],
            'data_nonce': updated_data['data_nonce'],
            'secret_key': updated_data['secret_key'],
            'secret_key_nonce': updated_data['secret_key_nonce'],
        })



class ShareTests(APITestCaseExtended):

    def setUp(self):
        self.test_email = u"test@example.com"
        self.test_email2 = u"test2@example.com"
        self.test_password = u"myPassword"
        self.test_authkey = u"c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
                            u"123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
        self.test_public_key = u"5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        self.test_secret_key = u"a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
        self.test_secret_key_enc = u"77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
                                   u"996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
                                   u"571a48eb"
        self.test_secret_key_nonce = u"f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce2 = u"f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = u"d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = u"abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    u"d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    u"a74b9b2452"
        self.test_private_key_nonce = u"4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = u"4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"

        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce = os.urandom(32).encode('hex'),
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce = os.urandom(32).encode('hex'),
            is_email_active=True
        )


    def test_list_shares_without_credentials(self):
        """
        Tests if someone gets shares without credentials
        """

        url = reverse('share')

        data = {}

        response = self.client.get(url, data, user=self.test_user_obj)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIsInstance(response.data.get('shares', False), list,
                        'We got some data even with a 401')


    def test_list_shares(self):
        """
        Tests if the initial listing of shares works
        """

        url = reverse('share')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                        'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('shares', False)), 0,
                        'Shares hold already data, but should not contain any data at the beginning')

    def test_insert_share(self):
        """
        Tests to insert the share and check the rights to access it
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': u"12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_id', False), False,
                            'Share id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'Share id is no valid UUID')

        new_share_id = str(response.data.get('share_id'))




        # lets try to get it back in the list

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                        'Shares do not exist in list shares response')
        self.assertGreater(len(response.data.get('shares', False)), 0,
                        'Shares hold some data')

        found = False

        for store in response.data.get('shares', []):
            if str(store.get('id', '')) == new_share_id:
                self.assertFalse(found,
                                 'Found our share twice in the returned list')
                found = True

                target_store = {
                    'id': UUID(new_share_id, version=4),
                    'data': str(initial_data['data']),
                    'data_nonce': unicode(initial_data['data_nonce']),
                    'user_id': self.test_user_obj.id,
                    'user_share_rights' : [{
                        'user_id' : self.test_user_obj.id,
                        'grant' : True,
                        'read' : True,
                        'key_nonce' : unicode(""),
                        'write' : True,
                        'key' : unicode(""),
                        'id' : store['user_share_rights'][0]['id']
                    }
                    ]
                }
                self.assertEqual(store, target_store)

        self.assertTrue(found, 'Did not find the share in the share list call')

        # lets try to get it back in detail

        url = reverse('share', kwargs={'uuid': new_share_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        target_store = {
            'id': UUID(new_share_id, version=4),
            'data': str(initial_data['data']),
            'data_nonce': unicode(initial_data['data_nonce']),
            'user_id': self.test_user_obj.id,
            'user_share_rights' : [{
                'user_id' : self.test_user_obj.id,
                'grant' : True,
                'read' : True,
                'key_nonce' : unicode(""),
                'write' : True,
                'key' : unicode(""),
                'id' : store['user_share_rights'][0]['id']
            }
            ]
        }

        self.assertEqual(response.data, target_store)

        # ok lets try to get the same share with a bad user

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # lets also check list view for another user

        url = reverse('share')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                        'Shares do not exist in list shares response')

        for store in response.data.get('shares', []):
            self.assertNotEqual(store.get('id', ''), new_share_id,
                                'Found our share in the list view of another user')

    def test_update_share(self):
        """
        Tests to update the share
        """

        # lets try to create a share

        url = reverse('share')

        initial_data = {
            'data': u"12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_id', False), False,
                            'Datastore id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'Datastore id is no valid UUID')

        new_share_id = str(response.data.get('share_id'))

        # Initial share set, so lets update it

        url = reverse('share', kwargs={'uuid': new_share_id})

        updated_data = {
            'data': u"123456",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, updated_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # lets try to get it back in detail

        url = reverse('share', kwargs={'uuid': new_share_id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        target_store = {
            'id': UUID(new_share_id, version=4),
            'data': str(updated_data['data']),
            'data_nonce': unicode(updated_data['data_nonce']),
            'user_id': self.test_user_obj.id,
            'user_share_rights' : [{
                'user_id' : self.test_user_obj.id,
                'grant' : True,
                'read' : True,
                'key_nonce' : unicode(""),
                'write' : True,
                'key' : unicode(""),
                'id' : response.data['user_share_rights'][0]['id']
            }
            ]
        }

        self.assertEqual(response.data, target_store)


class UserShareRightTest(APITestCaseExtended):

    def setUp(self):
        self.test_email = u"test@example.com"
        self.test_email2 = u"test2@example.com"
        self.test_password = u"myPassword"
        self.test_authkey = u"c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
                            u"123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
        self.test_public_key = u"5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        self.test_secret_key = u"a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
        self.test_secret_key_enc = u"77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
                                   u"996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
                                   u"571a48eb"
        self.test_secret_key_nonce = u"f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce2 = u"f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = u"d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = u"abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    u"d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    u"a74b9b2452"
        self.test_private_key_nonce = u"4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = u"4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"

        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce = os.urandom(32).encode('hex'),
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce = os.urandom(32).encode('hex'),
            is_email_active=True
        )


    def test_list_share_right_without_credentials(self):
        """
        Tests if someone gets share rights without credentials
        """

        url = reverse('share_right')

        data = {}

        response = self.client.get(url, data, user=self.test_user_obj)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIsInstance(response.data.get('share_rights', False), list,
                        'We got some data even with a 401')


    def test_list_share_right(self):
        """
        Tests if the initial listing of share rights works
        """

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('share_rights', False), list,
                        'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 0,
                        'Shares hold already data, but should not contain any data at the beginning')


        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=True
        )

        # and now insert our dummy share_right
        self.test_share_right1_ob = models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            title= u"Sexy Password",
            read= True,
            write= True,
            grant= True,
            user_id= str(self.test_user2_obj.id),
        )

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('share_rights', False), list,
                        'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 1,
                        'Shares should contain 1 entry')


    def test_read_share_with_no_rights(self):
        """
        Tests read share without rights
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        # Then lets try to get it with the wrong user

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsInstance(response.data.get('share_rights', False), list,
                              'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 0,
                         'No share should exist for this user')

        # let try to query it directly with wrong user

        url = reverse('share_right', kwargs={'uuid': str(self.test_share1_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(response.data.get('shares', False),
                         'Shares do not exist in list shares response')


    def test_grant_share_right_with_no_rights(self):
        """
        Tests grant share right without rights
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        # lets try to create a share right for this share

        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.test_share1_obj.id),
            'title': u"Sexy Password",
            'read': True,
            'write': True,
            'grant': True,
            'user_id': str(self.test_user2_obj.id),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)


        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_grant_share_right_with_right(self):
        """
        Tests to insert the share right and check the rights to access it
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )
        models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            user_id= self.test_user_obj.id,
            share_id= self.test_share1_obj.id,
            read= True,
            write= True,
            grant= True
        )

        # lets try to create a share right for this share

        url = reverse('share_right')

        initial_data = {
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'share_id': str(self.test_share1_obj.id),
            'title': u"Sexy Password",
            'read': True,
            'write': True,
            'grant': True,
            'user_id': str(self.test_user2_obj.id),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertNotEqual(response.data.get('share_right_id', False), False,
                            'Share id does not exist in share PUT answer')
        self.assertIsUUIDString(str(response.data.get('share_right_id', '')),
                                'Share id is no valid UUID')

        new_share_right_id = str(response.data.get('share_right_id'))




        # lets try to get the share back in the list now with rights

        url = reverse('share')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('shares', False), list,
                        'Shares do not exist in list shares response')
        self.assertEquals(len(response.data.get('shares', False)), 1,
                        'The should only be one share')


        # Then lets try to get it in the overview

        url = reverse('share_right')

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get('share_rights', False), list,
                        'Shares do not exist in list shares response')
        self.assertEqual(len(response.data.get('share_rights', False)), 1,
                        'One share should exist for this user')


        target_store = {
            'id': UUID(new_share_right_id, version=4),
            'share_id': self.test_share1_obj.id,
            'title': u"Sexy Password",
            'read': True,
            'write': True,
            'grant': True,
            'key': unicode(initial_data['key']),
            'key_nonce': unicode(initial_data['key_nonce']),
        }

        self.assertEqual(response.data.get('share_rights', False)[0], target_store)


    def test_delete_share_right_with_no_right(self):
        """
        Tests to delete the share right with no right
        """

        # Lets first insert our dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )
        models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=False
        )
        test_user_share_rights = models.User_Share_Right.objects.create(
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            share_id=self.test_share1_obj.id,
            read=False,
            write=False,
            grant=False
        )

        self.assertEqual(models.User_Share_Right.objects.filter(pk=test_user_share_rights.id).count(), 1,
                         'Exactly one share right with this id should exist')

        url = reverse('share_right', kwargs={'uuid': str(test_user_share_rights.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_delete_share_right_with_rights(self):
        """
        Tests to delete the share right with rights
        """

        # Lets first insert our dummy share
        test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )
        models.User_Share_Right.objects.create(
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=test_share1_obj.id,
            read=True,
            write=True,
            grant=True
        )

        test_user_share_rights = models.User_Share_Right.objects.create(
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            share_id=test_share1_obj.id,
            read=False,
            write=False,
            grant=False
        )

        self.assertEqual(models.User_Share_Right.objects.filter(pk=test_user_share_rights.id).count(), 1,
                         'Exactly one share right with this id should exist')

        url = reverse('share_right', kwargs={'uuid': str(test_user_share_rights.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(models.User_Share_Right.objects.filter(pk=test_user_share_rights.id).count(), 0,
                         'Share right with this id should have been deleted')



