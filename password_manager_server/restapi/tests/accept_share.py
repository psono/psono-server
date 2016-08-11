from django.core.urlresolvers import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status

from restapi import models

from base import APITestCaseExtended

import os
import random
import string

from uuid import UUID

class UserRightsAccept(APITestCaseExtended):
    """
    Test to accept share rights
    """

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "b"
        self.test_email3 = "test3@example.com"
        self.test_email_bcrypt3 = "c"
        self.test_username = "test@psono.pw"
        self.test_username2 = "test2@psono.pw"
        self.test_username3 = "test3@psono.pw"
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
        self.test_secret_key_nonce3 = "f580cc9500ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
        self.test_private_key_nonce3 = "4398a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"

        self.test_user_obj = models.User.objects.create(
            username=self.test_username,
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=os.urandom(32).encode('hex'),
            is_email_active=True
        )

        # Lets first insert our first dummy share for which share_rights can be accepted
        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        self.test_user2_obj = models.User.objects.create(
            username=self.test_username2,
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=os.urandom(32).encode('hex'),
            is_email_active=True
        )

        # Lets first insert our first dummy parent_share
        self.test_parent_share2_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        self.test_user3_obj = models.User.objects.create(
            username=self.test_username3,
            email=self.test_email3,
            email_bcrypt=self.test_email_bcrypt3,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce3,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce3,
            user_sauce=os.urandom(32).encode('hex'),
            is_email_active=True
        )

        # Lets first insert our first dummy parent_share
        self.test_parent_share3_obj = models.Share.objects.create(
            user_id=self.test_user3_obj.id,
            data="my-data",
            data_nonce="12345"
        )

    def test_accept_share_right_no_uuid(self):
        """
        Tests to accept a share right without uuid
        """

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={})

        initial_data = {
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_accept_share_right_with_parent_share(self):
        """
        Tests to accept a share right with a parent_share
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_share_id': test_parent_share1_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('share_data_nonce', False), self.test_share1_obj.data_nonce)
        self.assertEqual(response.data.get('share_data', False), self.test_share1_obj.data)
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'share id is no valid UUID')

        saved_user_share_right = models.User_Share_Right.objects.get(pk=str(test_share_right1_obj.id))

        self.assertEqual(saved_user_share_right.title, "", "Title should be empty")
        self.assertEqual(saved_user_share_right.title_nonce, "", "Title nonce should be empty")
        self.assertEqual(saved_user_share_right.accepted, True, "Accepted flag should be true")
        self.assertEqual(saved_user_share_right.key, initial_data['key'], "Key should be new key")
        self.assertEqual(saved_user_share_right.key_nonce, initial_data['key_nonce'], "Key nonce should be new key")
        self.assertEqual(saved_user_share_right.key_type, "symmetric", "Key type should now be symmetric")

    def test_accept_share_right_with_duplicate_link_id(self):
        """
        Tests to accept a share right with duplicate_link_id
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        test_share_right2_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user3_obj.id,
            read=True,
            write=False,
            grant=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        test_parent_share2_obj = models.Share.objects.create(
            user_id=self.test_user3_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share2_obj.id,
            owner_id=self.test_user3_obj.id,
            user_id=self.test_user3_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_share_id': test_parent_share1_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # lets try to create an inherited share right for share2 and other user
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_share_id': test_parent_share2_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user3_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_accept_share_right_in_share_with_no_grant_right_on_share(self):
        """
        Tests to accept a share right in share with no grant right on share
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=False
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_share_id': test_parent_share1_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_accept_share_right_with_badly_formatted_parent_share_uuid(self):
        """
        Tests to accept a share right with badly formatted parent share uuid
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_share_id': "123456",
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_share_right_with_badly_formatted_parent_datastore_uuid(self):
        """
        Tests to accept a share right with badly formatted parent datastore uuid
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_datastore_id': "123456",
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_share_right_with_no_share_right_uuid(self):
        """
        Tests to accept a share right with no share right uuid
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': '581d7299-b818-48d5-984b-812b43522464'})

        initial_data = {
            'parent_share_id': test_parent_share1_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_share_right_with_no_parent_share_nor_datastore(self):
        """
        Tests to accept a share right with no parent_share nor datastore
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': '581d7299-b818-48d5-984b-812b43522464'})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_share_right_with_parent_share_and_datastore(self):
        """
        Tests to accept a share right with parent_share and datastore
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )


        test_datastore1_obj = models.Data_Store.objects.create(
            user_id=self.test_user2_obj.id,
            type="my-type",
            description= "my-description",
            data= "12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': '581d7299-b818-48d5-984b-812b43522464'})

        initial_data = {
            'parent_share_id': test_parent_share1_obj.id,
            'parent_datastore_id': test_datastore1_obj.id,
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_accept_share_right_with_badly_formatted_share_right_uuid(self):
        """
        Tests to accept a share right with badly formatted share right uuid
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': '581d7299-b818-48d5-984b-812b43522464'})

        initial_data = {
            'link_id': "223545",
            'parent_share_id': test_parent_share1_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_accept_share_right_with_parent_datastore(self):
        """
        Tests to accept a share right with parent datastore
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        test_datastore1_obj = models.Data_Store.objects.create(
            user_id=self.test_user2_obj.id,
            type="my-type",
            description= "my-description",
            data= "12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_datastore_id': test_datastore1_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('share_data_nonce', False), self.test_share1_obj.data_nonce)
        self.assertEqual(response.data.get('share_data', False), self.test_share1_obj.data)
        self.assertIsUUIDString(str(response.data.get('share_id', '')),
                                'share id is no valid UUID')

        saved_user_share_right = models.User_Share_Right.objects.get(pk=str(test_share_right1_obj.id))

        self.assertEqual(saved_user_share_right.title, "", "Title should be empty")
        self.assertEqual(saved_user_share_right.title_nonce, "", "Title nonce should be empty")
        self.assertEqual(saved_user_share_right.accepted, True, "Accepted flag should be true")
        self.assertEqual(saved_user_share_right.key, initial_data['key'], "Key should be new key")
        self.assertEqual(saved_user_share_right.key_nonce, initial_data['key_nonce'], "Key nonce should be new key")
        self.assertEqual(saved_user_share_right.key_type, "symmetric", "Key type should now be symmetric")

    def test_accept_not_existing_share_right(self):
        """
        Tests to accept a not existent share right
        """

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': "c705baca-ea0f-4848-b16e-e95fe80652f2"})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_share_id': self.test_share1_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_accept_share_right_with_not_existing_parent_share(self):
        """
        Tests to accept a share right with a parent share for which the user has no rights
        """

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9",
            'parent_share_id': "b084e8cd-ff45-49a1-8ad7-f74e7c0a301d"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_accept_share_right_with_not_existing_datastore(self):
        """
        Tests to accept a share right with a parent datastore that does not exist
        """

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9",
            'parent_datastore_id': "b084e8cd-ff45-49a1-8ad7-f74e7c0a301d"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_accept_share_right_without_parent_share_rights(self):
        """
        Tests to accept a a share right with a parent for which the user has no rights
        """

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9",
            'parent_share_id': self.test_parent_share2_obj.id
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_accept_share_right_with_no_rights_on_datastore(self):
        """
        Tests to accept a share right with a parent datastore for which the user has no rights
        """

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        test_datastore1_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= "12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9",
            'parent_datastore_id': test_datastore1_obj.id
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.post(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_accept_share_right(self):
        """
        Tests GET method to accept a share right
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_share_id': test_parent_share1_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_accept_share_right(self):
        """
        Tests PUT method to accept a share right
        """

        models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            read=True,
            write=False,
            grant=True,
            accepted=True
        )

        test_share_right1_obj = models.User_Share_Right.objects.create(
            share_id=self.test_share1_obj.id,
            owner_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            read=True,
            write=False,
            grant=True
        )

        test_parent_share1_obj = models.Share.objects.create(
            user_id=self.test_user2_obj.id,
            data="my-data",
            data_nonce="12345"
        )

        models.User_Share_Right.objects.create(
            share_id=test_parent_share1_obj.id,
            owner_id=self.test_user2_obj.id,
            user_id=self.test_user2_obj.id,
            read=False,
            write=True,
            grant=False,
            accepted=True
        )

        # lets try to create an inherited share right for share2
        url = reverse('share_right_accept', kwargs={'uuid': str(test_share_right1_obj.id)})

        initial_data = {
            'link_id': "2455761a-dbb8-4cbc-971c-428aa4d471a3",
            'parent_share_id': test_parent_share1_obj.id,
            'key': "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a55e3c",
            'key_nonce': "4298a9ab3d9d5d8643dfd4445adc30301b5654f650497fb9"
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.put(url, initial_data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
