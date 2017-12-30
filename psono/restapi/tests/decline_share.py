from django.urls import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status

from restapi import models

from .base import APITestCaseExtended
from ..utils import readbuffer

import os

from uuid import UUID

class UserRightsDecline(APITestCaseExtended):
    """
    Test to decline share rights
    """

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "b"
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
        self.test_secret_key_nonce2 = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
        self.test_private_key_nonce3 = "4398a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"

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
            user_sauce='e5e74f178b61e6fd4aa8bbfcc7d797abf3b1ed1bfa89a8850967c4b463468ccd',
            is_email_active=True
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce='fdc12f5d2904a40eed1076175d729dade3c395ea3d54d91ef0769330b0b6cfa0',
            is_email_active=True
        )
    def test_decline_share_right_no_uuid(self):
        """
        Tests to decline a share right without uuid
        """

        # lets try to create an inherited share right for share2
        url = reverse('share_right_decline')

        initial_data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_decline_share_right(self):
        """
        Tests to decline a share right
        """

        # Lets first insert our first dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer("my-data"),
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            creator_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_decline')

        initial_data = {
            'share_right_id': str(self.test_share_right1_obj.id)
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        saved_user_share_right = models.User_Share_Right.objects.get(pk=str(self.test_share_right1_obj.id))

        self.assertEqual(saved_user_share_right.title, "", "Title should be empty")
        self.assertEqual(saved_user_share_right.title_nonce, "", "Title nonce should be empty")
        self.assertEqual(saved_user_share_right.accepted, False, "Accepted flag should be false")
        self.assertEqual(saved_user_share_right.key, "", "Key should be empty")
        self.assertEqual(saved_user_share_right.key_nonce, "", "Key nonce should be empty")
        self.assertEqual(saved_user_share_right.key_type, "", "Key type should be empty")

    def test_decline_not_existent_share_right(self):
        """
        Tests to decline a not existent share right
        """

        # lets try to create an inherited share right for share2
        url = reverse('share_right_decline')

        initial_data = {
            'share_right_id': "c705baca-ea0f-4848-b16e-e95fe80652f2"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_decline_share_right(self):
        """
        Tests GET method to decline a share right
        """

        # Lets first insert our first dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer("my-data"),
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            creator_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_decline')

        initial_data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_decline_share_right(self):
        """
        Tests PUT method to decline a share right
        """

        # Lets first insert our first dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer("my-data"),
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            creator_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_decline')

        initial_data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_decline_share_right(self):
        """
        Tests DELETE method to decline a share right
        """

        # Lets first insert our first dummy share
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer("my-data"),
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        self.test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            creator_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_decline')

        initial_data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.delete(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
