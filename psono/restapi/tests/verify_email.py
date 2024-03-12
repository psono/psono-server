
from django.test.utils import override_settings
from django.urls import reverse

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models
from restapi.utils import generate_activation_code, get_static_bcrypt_hash_from_email

class VerifyEmailTests(APITestCaseExtended):
    """
    Tests verification of the email address
    """

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email2 = "test2@example.com"
        self.test_username = "test@psono.pw"
        self.test_username2 = "test2@psono.pw"
        self.test_password = "myPassword"
        self.test_authkey = "c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7" \
                            "123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
        self.test_public_key = "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        self.test_secret_key = "a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
        self.test_secret_key_enc = "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422" \
                                   "996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011" \
                                   "571a48eb"
        self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce2 = "f580cc9902ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d8d5d8643dfd4445adc30301b565ab650497fb9"

        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=get_static_bcrypt_hash_from_email(self.test_email),
            username=self.test_username,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='8b32efae0a4940bafa236ee35ee975f71833860b7fa747d44659717b18719d84',
            is_email_active=False
        )
        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=get_static_bcrypt_hash_from_email(self.test_email2),
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='14f79675e9b28c25d633b0e4511beb041cca41da864bd36c94c67d60c1d3f716',
            is_email_active=True
        )
        self.activation_code = generate_activation_code(self.test_email)
        self.activation_code2 = generate_activation_code(self.test_email2)


    def test_put(self):
        """
        Tests PUT
        """

        url = reverse('authentication_verify_email')

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_post_successfully(self):
        """
        Tests POST and successfully verify an email address
        """

        url = reverse('authentication_verify_email')

        data = {
            'activation_code': self.activation_code,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        user1 = models.User.objects.get(pk=self.test_user_obj.pk)

        self.assertTrue(user1.is_email_active)

    @override_settings(ACTIVATION_LINK_TIME_VALID=-10)
    def test_post_with_activation_link_being_too_old(self):
        """
        Tests POST with an activation link that is too old and has already expired
        """

        url = reverse('authentication_verify_email')

        data = {
            'activation_code': self.activation_code,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    def test_post_user_has_already_verified_email(self):
        """
        Tests POST with a user that already has used the activation code to verify his email address
        """

        url = reverse('authentication_verify_email')

        data = {
            'activation_code': self.activation_code2,
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    def test_post_malformed_activation_code(self):
        """
        Tests POST with a malformed activation code
        """

        url = reverse('authentication_verify_email')

        data = {
            'activation_code': "abc",
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete(self):
        """
        Tests DELETE
        """

        url = reverse('authentication_verify_email')

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_get(self):
        """
        Tests GET
        """

        url = reverse('authentication_verify_email')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


