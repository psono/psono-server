import base64

from django.urls import reverse
from django.conf import settings
from django.test.utils import override_settings

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models

import random
import string
import os
import binascii


class AvatarImageTest(APITestCaseExtended):
    """
    Test to read an avatar_image (GET)
    """
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='90272aaf01a2d525223f192aca069e7f5661b3a0f1b1a91f9b16d493fdf15295',
            is_email_active=True
        )

        self.test_email2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt2 = "b"
        self.test_username2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey2 = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
        self.test_public_key2 = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key2 = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key2 = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce2 = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce2 = 'a67fef1ff29eb8f866feaccad336fc6311fa4c71bc183b14c8fceff7416add99'

        self.test_user_obj2 = models.User.objects.create(
            username=self.test_username2,
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            authkey="abc",
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )
        self.avatar_image_data_base64='R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
        self.avatar_image = models.Avatar.objects.create(
            user_id=self.test_user_obj.id,
            mime_type='image/gif',
            data=base64.b64decode(self.avatar_image_data_base64)
        )



    def test_read_successful(self):
        """
        Tests to read a specific avatar_image
        """

        url = reverse('avatar_image', kwargs={'avatar_id': self.avatar_image.id, 'user_id': self.test_user_obj.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.headers['content-type'], 'image/gif')
        self.assertEqual(response.headers['cache-control'], 'max-age=2592000, public')
        self.assertEqual(response.headers['pragma'], 'cache')
        self.assertEqual(base64.b64encode(response.content).decode(), self.avatar_image_data_base64)

    def test_read_specific_with_wrong_user_id(self):
        """
        Tests to read a specific avatar_image with wrong user id that doesn't exist
        """

        url = reverse('avatar_image', kwargs={'avatar_id': self.avatar_image.id, 'user_id': '1bcc5b2d-3eca-496a-98b1-a86734fd0d02'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['non_field_errors'], ['NO_PERMISSION_OR_NOT_EXIST'])
    def test_read_specific_with_wrong_avatar_image_id(self):
        """
        Tests to read a specific avatar_image with wrong avatar_image id that doesn't exist
        """

        url = reverse('avatar_image', kwargs={'avatar_id': '1bcc5b2d-3eca-496a-98b1-a86734fd0d02', 'user_id': self.test_user_obj.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['non_field_errors'], ['NO_PERMISSION_OR_NOT_EXIST'])

    def test_read_specific_other_user(self):
        """
        Tests to read a specific avatar_image of a different user (which should work)
        """

        url = reverse('avatar_image', kwargs={'avatar_id': self.avatar_image.id, 'user_id': self.test_user_obj.id})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj2)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.headers['content-type'], 'image/gif')
        self.assertEqual(response.headers['cache-control'], 'max-age=2592000, public')
        self.assertEqual(response.headers['pragma'], 'cache')
        self.assertEqual(base64.b64encode(response.content).decode(), self.avatar_image_data_base64)

    def test_read_unauthenticated(self):
        """
        Tests to read unauthetnicated
        """

        url = reverse('avatar_image', kwargs={'avatar_id': self.avatar_image.id, 'user_id': self.test_user_obj.id})

        data = {}

        #self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.headers['content-type'], 'image/gif')
        self.assertEqual(response.headers['cache-control'], 'max-age=2592000, public')
        self.assertEqual(response.headers['pragma'], 'cache')
        self.assertEqual(base64.b64encode(response.content).decode(), self.avatar_image_data_base64)
