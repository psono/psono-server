from django.core.management import call_command
from django.test import TestCase
from django.conf import settings
from django.contrib.auth.hashers import check_password

from restapi import models
from restapi.utils import generate_authkey

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import nacl.encoding
import nacl.utils
import nacl.secret
import bcrypt
import hashlib

class CommandCreateuserTestCase(TestCase):

    def test_createuser(self):

        username = 'username@example.com'
        password = 'myPassword'
        email = 'email@something.com'

        args = [username, password, email]
        opts = {}

        out = StringIO()
        call_command('createuser', stdout=out, *args, **opts)

        user = models.User.objects.get(username=username)

        email_bcrypt = bcrypt.hashpw(email.encode('utf-8'), settings.EMAIL_SECRET_SALT).replace(settings.EMAIL_SECRET_SALT, '', 1)
        crypto_box = nacl.secret.SecretBox(hashlib.sha256(settings.DB_SECRET).hexdigest(), encoder=nacl.encoding.HexEncoder)

        self.assertEqual(crypto_box.decrypt(nacl.encoding.HexEncoder.decode(user.email)), email)
        self.assertEqual(user.email_bcrypt, email_bcrypt)
        self.assertTrue(check_password(str(generate_authkey(username, password)), user.authkey))
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_email_active)




