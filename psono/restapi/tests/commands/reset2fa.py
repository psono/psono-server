from django.core.management import call_command
from django.test import TestCase
from django.contrib.auth.hashers import make_password
from django.utils import timezone

from restapi import models
from restapi.utils import encrypt_with_db_secret

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class CommandReset2FaTestCase(TestCase):

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
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
            duo_enabled=True,
            google_authenticator_enabled=True,
            yubikey_otp_enabled=True,
        )

        models.Google_Authenticator.objects.create(
                user=self.test_user_obj,
                title='My TItle',
                secret='1234'
        )

        models.Duo.objects.create(
            user=self.test_user_obj,
            title='My Sweet Title',
            duo_integration_key='duo_integration_key',
            duo_secret_key=encrypt_with_db_secret('duo_secret_key'),
            duo_host='duo_secret_key',
            enrollment_user_id='enrollment_user_id',
            enrollment_activation_code='enrollment_activation_code',
            enrollment_expiration_date=timezone.now(),
        )

        models.Yubikey_OTP.objects.create(
                user=self.test_user_obj,
                title='My TItle',
                yubikey_id='1234'
        )


    def test_promoteuser_to_superuser(self):
        """
        Tests to promote a user to superuser
        """

        args = [self.test_username]
        opts = {}

        out = StringIO()
        call_command('reset2fa', stdout=out, *args, **opts)

        user = models.User.objects.get(username=self.test_username)

        self.assertFalse(user.duo_enabled)
        self.assertFalse(user.google_authenticator_enabled)
        self.assertFalse(user.yubikey_otp_enabled)
        self.assertFalse(models.Duo.objects.filter(user=user).exists())
        self.assertFalse(models.Google_Authenticator.objects.filter(user=user).exists())
        self.assertFalse(models.Yubikey_OTP.objects.filter(user=user).exists())

    def test_promoteuser_that_does_not_exist(self):
        """
        Tests to promote a user to superuser that does not exist
        """

        args = ['idontexist@psono.pw']
        opts = {}

        out = StringIO()
        call_command('reset2fa', stdout=out, *args, **opts)

        self.assertEqual(out.getvalue(), 'User does not exist\n')




