from django.core.management import call_command
from django.test import TestCase
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

from restapi import models

import binascii
import random
import string
import os
from io import StringIO

import hashlib

class CommandCleartokenTestCase(TestCase):
    #
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
        self.test_user_sauce = 'd22f5797cfd438f212bb0830da488f0555487697ad4041bbcbf5b08bc297e117'
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

        # Lets put one tokens validity into the future, and one into the past
        self.token = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        models.Token.objects.create(
            key= hashlib.sha512(self.token.encode()).hexdigest(),
            user=self.test_user_obj,
            valid_till=timezone.now() + timedelta(seconds=10)
        )

        self.token2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        models.Token.objects.create(
            key= hashlib.sha512(self.token2.encode()).hexdigest(),
            user=self.test_user_obj,
            valid_till = timezone.now() - timedelta(seconds=10)
        )


    def test_cleartoken(self):

        self.assertEqual(models.Token.objects.count(), 2)

        args = []
        opts = {}

        out = StringIO()
        call_command('cleartoken', stdout=out, *args, **opts)

        self.assertEqual(models.Token.objects.count(), 1)




