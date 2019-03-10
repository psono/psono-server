from django.core.management import call_command
from django.test import TestCase
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password

from restapi import models
from restapi.utils import generate_authkey, decrypt_with_db_secret, get_static_bcrypt_hash_from_email

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import bcrypt

class CommandCreateuserTestCase(TestCase):

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = bcrypt.hashpw(self.test_email.encode(), settings.EMAIL_SECRET_SALT.encode()).decode().replace(settings.EMAIL_SECRET_SALT, '', 1)
        self.test_username = "test@psono.pw"
        self.test_password = "myPassword"
        self.test_authkey = "c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
                            "123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
        self.test_public_key = "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        self.test_secret_key = "a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
        self.test_secret_key_enc = "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
                                   "996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
                                   "571a48eb"
        self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"

        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='082202ea53a9f64459b8217ebbdea19f6cb385d8d529327053f54a9b9861dcf1',
            is_email_active=True,
            is_active=False,
        )

    def test_generate_authkey(self):
        """
        Tests generate authkey function
        """

        username = 'username@example.com'
        password = 'myPassword'
        authkey = '2d67919ba1021eb38b0647cfdf926aab6d25c7465a179551894a2b2d6fc1c8a8183076c5f7b7f7245419c3cf57c574f84386a1b1e30cddfc10606c67a28e2587'

        self.assertEqual(generate_authkey(username, password).decode(), authkey)

    def test_createuser(self):
        """
        Tests to create a user
        """

        username = 'username@example.com'
        password = 'myPassword'
        email = 'email@something.com'

        args = [username, password, email]
        opts = {}

        out = StringIO()
        call_command('createuser', stdout=out, *args, **opts)

        user = models.User.objects.get(username=username)

        email_bcrypt = get_static_bcrypt_hash_from_email(email)

        self.assertEqual(decrypt_with_db_secret(user.email), email)
        self.assertEqual(user.email_bcrypt, email_bcrypt)
        self.assertTrue(check_password(generate_authkey(username, password).decode(), user.authkey))
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_email_active)

    def test_createuser_email_already_exist(self):
        """
        Tests to create a user where the email already exist
        """

        username = 'username@example.com'
        password = 'myPassword'
        email = self.test_email

        args = [username, password, email]
        opts = {}

        out = StringIO()
        call_command('createuser', stdout=out, *args, **opts)


        found = True
        try:
            models.User.objects.get(username=username)
        except models.User.DoesNotExist:
            found = False

        self.assertFalse(found)
        self.assertEqual(out.getvalue(), 'Email already exists.\n')

    def test_createuser_username_already_exist(self):
        """
        Tests to create a user where the username already exists
        """

        username = self.test_username
        password = 'myPassword'
        email = 'email@something.com'

        args = [username, password, email]
        opts = {}

        out = StringIO()
        call_command('createuser', stdout=out, *args, **opts)

        found = True
        try:
            models.User.objects.get(username=username)
        except models.User.DoesNotExist:
            found = False

        self.assertTrue(found) # Must be true as we already created it before
        self.assertEqual(out.getvalue(), 'Username already exists.\n')




