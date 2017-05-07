from django.core.urlresolvers import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status
from base import APITestCaseExtended

from restapi import models

import random
import string

class UserDeleteSecretLinkTest(APITestCaseExtended):
    """
    Test to delete a secret_link(PUT)
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='90272aaf01a2d525223f192aca069e7f5661b3a0f1b1a91f9b16d493fdf15295',
            is_email_active=True
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= "12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        # create share 1
        url = reverse('share')

        self.initial_data1 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '5993584d-bf73-4679-a92a-ea333640cfdd',
            'parent_datastore_id': self.test_datastore_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response1 = self.client.post(url, self.initial_data1)

        self.assertEqual(self.response1.status_code, status.HTTP_201_CREATED)


    def test_delete_without_link_id(self):
        """
        Tests to delete a link without link_id
        """

        url = reverse('secret_link')

        data = {

        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_delete_with_not_existing_link_id(self):
        """
        Tests to delete a link with not existing link_id
        """

        url = reverse('secret_link')

        link_id = '1e541d96-ff3f-4161-9b50-dae234a7e6b8'

        data = {
            'link_id': link_id
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class UserMoveSecretLinkTest(APITestCaseExtended):
    """
    Test to move a secret_link(POST)
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='90272aaf01a2d525223f192aca069e7f5661b3a0f1b1a91f9b16d493fdf15295',
            is_email_active=True
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= "12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        # create share 1
        url = reverse('share')

        self.initial_data1 = {
            'data': "12345",
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key': ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            'key_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'key_type': 'symmetric',
            'link_id': '5993584d-bf73-4679-a92a-ea333640cfdd',
            'parent_datastore_id': self.test_datastore_obj.id,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        self.response1 = self.client.post(url, self.initial_data1)

        self.assertEqual(self.response1.status_code, status.HTTP_201_CREATED)


    def test_move_without_link_id(self):
        """
        Tests to move a link without link_id
        """

        url = reverse('secret_link')

        data = {
            'new_parent_share_id': '062f7167-e0ea-4c7c-a490-3b6993d43f7e',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_move_without_new_parent_share_id_nor_new_parent_datastore_id(self):
        """
        Tests to move a link without new_parent_share_id nor new_parent_datastore_id
        """

        url = reverse('secret_link')

        data = {
            'link_id': 'ebf581a5-7113-4861-866f-a570b79ae860',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_move_without_existing_link_id(self):
        """
        Tests to move a link without existing link_id
        """

        url = reverse('secret_link')

        data = {
            'link_id': 'd5331d29-1a33-455e-8d9d-6ad9ea3c0a0c',
            'new_parent_share_id': 'e5d173bf-bba5-4cd3-b1a4-a8889f754543',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)