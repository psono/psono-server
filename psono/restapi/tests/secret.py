from django.urls import reverse
from django.contrib.auth.hashers import make_password
from django.conf import settings

from rest_framework import status
from .base import APITestCaseExtended
from ..utils import readbuffer
from restapi import models
from mock import patch

import random
import string
import binascii
import os

from ..utils import encrypt_with_db_secret

BAD_URL='BAD_URL'

def mock_request_post(url, data=None, json=None, **kwargs):
    if url == BAD_URL:
        raise Exception


class UserCreateSecretTest(APITestCaseExtended):
    """
    Test to create a secret (PUT)
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
            authkey=make_password(self.test_authkey2),
            public_key=self.test_public_key2,
            private_key=self.test_private_key2,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key2,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce=self.test_user_sauce2,
            is_email_active=True
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= readbuffer("12345"),
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer("my-data"),
            data_nonce="12345"
        )

        self.test_user_share_right1_obj = models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share1_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
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


    def test_without_data(self):
        """
        Tests to create a secret without data
        """

        url = reverse('secret')

        data = {
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_without_data_nonce(self):
        """
        Tests to create a secret without data nonce
        """

        url = reverse('secret')

        data = {
            'data': '12345',
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_secret_in_datastore(self):
        """
        Tests to create a secret successfully in a datastore
        """

        url = reverse('secret')

        data = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'data': '12345',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


    def test_create_secret_without_parent_datastore_nor_share(self):
        """
        Tests to create a secret successfully in a datastore
        """

        url = reverse('secret')

        data = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            # 'parent_datastore_id': str(self.test_datastore_obj.id),
            'data': '12345',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_secret_in_datastore_that_the_user_does_not_own(self):
        """
        Tests to create a secret in a datastore that the user has no access permissions
        """

        self.test_datastore_obj.user = self.test_user_obj2
        self.test_datastore_obj.save()

        url = reverse('secret')

        data = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'data': '12345',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_secret_in_share_without_write_permissions(self):
        """
        Tests to create a secret faulty in a share without write permissions
        """

        self.test_user_share_right1_obj.write = False
        self.test_user_share_right1_obj.save()

        url = reverse('secret')

        data = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            'parent_share_id': str(self.test_share1_obj.id),
            'data': '12345',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_create_secret_in_share_that_does_not_exist(self):
        """
        Tests to create a secret faulty in a share that does not exist
        """

        self.test_user_share_right1_obj.write = False
        self.test_user_share_right1_obj.save()

        url = reverse('secret')

        data = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            'parent_share_id': "9a4648b6-7832-403b-bcdf-42f825db0311",
            'data': '12345',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_duplicate_nonce(self):
        """
        Tests to create a share, while reusing a nonce
        """

        url = reverse('secret')

        first_secret = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'data': '12345',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, first_secret)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        second_secret = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'data': '123456',
            'data_nonce': first_secret['data_nonce'],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, second_secret)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_duplicate_link_id(self):
        """
        Tests to create a share, while reusing a link id
        """

        url = reverse('secret')

        first_secret = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'data': '12345',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, first_secret)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        second_secret = {
            'link_id': first_secret['link_id'],
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'data': '123456',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, second_secret)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserGetSecretTest(APITestCaseExtended):
    """
    Test to get a secret (GET)
    """
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "b"
        self.test_email3 = "test3@example.com"
        self.test_email_bcrypt3 = "test3@example.com"
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
        self.test_secret_key_nonce2 = "f580cc9902ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce3 = "f580c29902ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d8d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce3 = "4228a9ab3d8d5d8643dfd4445adc30301b565ab650497fb9"

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
            user_sauce='6b84c6bca05de45714f224e4707fa4e02a59fa21b1e6539f5f3f35fdbf914022',
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
            user_sauce='4b01f5914b95005b011442ff6a88039627909e77e67f84066973b22131958ac2',
            is_email_active=True
        )
        self.test_user3_obj = models.User.objects.create(
            email=self.test_email3,
            email_bcrypt=self.test_email_bcrypt3,
            username=self.test_username3,
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce3,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce3,
            user_sauce='dd8e55859b0542320fc4c442cfa7d751ef16ffcabbbefd0129c10cdc0ea79b00',
            is_email_active=True
        )
        self.test_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer('12345'),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= readbuffer("12345"),
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.secret_link_obj = models.Secret_Link.objects.create(
            link_id = '0493017f-47b0-446e-9a41-6533721ade71',
            secret_id = self.test_secret_obj.id,
            parent_datastore_id = self.test_datastore_obj.id,
            parent_share_id = None
        )

        self.test_secret2_obj = models.Secret.objects.create(
            user_id=self.test_user2_obj.id,
            data=readbuffer('12345'),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )


    def test_read_secret_success(self):
        """
        Tests to read a specific secret successful
        """

        url = reverse('secret', kwargs={'secret_id': str(self.test_secret_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_without_uuid_and_existing_secrets(self):
        """
        Tests to get all shares without specifying a uuid, while having some secrets
        """

        url = reverse('secret')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_without_uuid_and_no_existing_secrets(self):
        """
        Tests to get all shares without specifying a uuid, while having some secrets
        """

        url = reverse('secret')

        data = {}

        self.client.force_authenticate(user=self.test_user3_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_with_badly_formatted_uuid(self):
        """
        Tests to get a specific share without rights
        """

        url = reverse('secret', kwargs={'secret_id': "12345"})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_with_not_existing_secret(self):
        """
        Tests to get a specific share without rights
        """

        url = reverse('secret', kwargs={'secret_id': 'cf84fbd5-c606-4d5b-aa96-88c68a06cde4'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_without_rights(self):
        """
        Tests to get a specific share without rights
        """

        url = reverse('secret', kwargs={'secret_id': str(self.test_secret2_obj.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


    def test_delete_secret_update(self):
        """
        Tests DELETE method on user_update
        """

        url = reverse('secret')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class UserUpdateSecretTest(APITestCaseExtended):
    """
    Test to update a secret (POST)
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
        self.test_secret_key_nonce2 = "f580cc9902ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_private_key = "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        self.test_private_key_enc = "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52" \
                                    "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576" \
                                    "a74b9b2452"
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = "4298a9ab3d8d5d8643dfd4445adc30301b565ab650497fb9"

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
            user_sauce='8b32efae0a4940bafa236ee35ee975f71833860b7fa747d44659717b18719d84',
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
            user_sauce='14f79675e9b28c25d633b0e4511beb041cca41da864bd36c94c67d60c1d3f716',
            is_email_active=True
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= readbuffer("12345"),
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )


        url = reverse('secret')

        data = {
            'link_id': '0f3ff8d2-213a-47f3-bd58-fc88cb0220f9',
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'data': '12345',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.secret_id = response.data['secret_id']

        self.test_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=readbuffer('12345'),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

    def test_with_badly_formatted_uuid(self):
        """
        Tests to update a specific secret with a malformed UUID
        """

        url = reverse('secret')

        data = {
            'secret_id': '12345'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_with_not_existing_secret(self):
        """
        Tests to update a specific secret that does not exist
        """

        url = reverse('secret')

        data = {
            'secret_id': 'cf84fbd5-c606-4d5b-aa96-88c68a06cde4'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_without_rights(self):
        """
        Tests to update a specific secret without rights
        """

        url = reverse('secret')

        data = {
            'secret_id': str(self.test_secret_obj.id),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_success(self):
        """
        Tests to update a specific secret successful
        """

        url = reverse('secret')

        data = {
            'secret_id': str(self.secret_id),
            'data': '123457',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        updated_secret = models.Secret.objects.get(pk=self.secret_id)

        self.assertEqual(readbuffer(updated_secret.data), data['data'],
                            'data in secret was not updated')

        self.assertEqual(str(updated_secret.data_nonce), data['data_nonce'],
                            'data_nonce in secret was not updated')

        self.assertEqual(models.Secret_History.objects.filter(secret=updated_secret).count(), 1)


    @patch('requests.post', side_effect=mock_request_post)
    def test_success_with_callback_url(self, mock_request_post):
        """
        Tests to update a specific secret with a callback url
        """

        secret = models.Secret.objects.get(pk=str(self.secret_id))
        secret.callback_url = 'https://example.com'
        secret.save()

        url = reverse('secret')

        data = {
            'secret_id': str(self.secret_id),
            'data': '123457',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(mock_request_post.call_count, 1)

        target_data = {
            'event': 'UPDATE_SECRET_SUCCESS',
            'secret_id': str(self.secret_id)
        }

        target_headers = {'content-type': 'application/json'}
        target_auth = None

        mock_request_post.assert_any_call(secret.callback_url, data=target_data, headers=target_headers, auth=target_auth, timeout=5.0)


    @patch('requests.post', side_effect=mock_request_post)
    def test_success_with_updated_callback_url(self, mock_request_post):
        """
        Tests to update a specific secret with a callback url in the update parameters
        """

        url = reverse('secret')

        data = {
            'secret_id': str(self.secret_id),
            'data': '123457',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            'callback_url': 'https://example.com',
            'callback_user': 'myUser',
            'callback_pass': 'myPass'
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(mock_request_post.call_count, 1)

        target_data = {
            'event': 'UPDATE_SECRET_SUCCESS',
            'secret_id': str(self.secret_id)
        }

        target_headers = {'content-type': 'application/json'}
        target_auth = (data.get('callback_user'), data.get('callback_pass'))

        mock_request_post.assert_any_call(data.get('callback_url'), data=target_data, headers=target_headers, auth=target_auth, timeout=5.0)


    @patch('requests.post', side_effect=mock_request_post)
    def test_success_with_callback_url_that_is_malformed(self, mock_request_post):
        """
        Tests to update a specific secret with a callback url that is invalid. The function should pass anyway without
        exception for the user
        """

        secret = models.Secret.objects.get(pk=str(self.secret_id))
        secret.callback_url = BAD_URL
        secret.save()

        url = reverse('secret')

        data = {
            'secret_id': str(self.secret_id),
            'data': '123457',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(mock_request_post.call_count, 1)


    @patch('requests.post', side_effect=mock_request_post)
    def test_success_with_callback_url_user_and_pass(self, mock_request_post):
        """
        Tests to update a specific secret with a callback url, user and password
        """

        secret = models.Secret.objects.get(pk=str(self.secret_id))
        secret.callback_url = 'https://example.com'
        secret.callback_user = 'AnyUserName'
        callback_pass = 'PassWord'
        secret.callback_pass = encrypt_with_db_secret(callback_pass)
        secret.save()

        url = reverse('secret')

        data = {
            'secret_id': str(self.secret_id),
            'data': '123457',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(mock_request_post.call_count, 1)

        target_data = {
            'event': 'UPDATE_SECRET_SUCCESS',
            'secret_id': str(self.secret_id)
        }

        target_headers = {'content-type': 'application/json'}
        target_auth = (secret.callback_user, callback_pass)

        mock_request_post.assert_any_call(secret.callback_url, data=target_data, headers=target_headers, auth=target_auth, timeout=5.0)


    @patch('requests.post', side_effect=mock_request_post)
    def test_success_with_callback_url_user_and_pass_that_is_not_proper_encrypted(self, mock_request_post):
        """
        Tests to update a specific secret with a callback url, user and password, that can fail (e.g empty, Null, ...)
        """

        secret = models.Secret.objects.get(pk=str(self.secret_id))
        secret.callback_url = 'https://example.com'
        secret.callback_user = 'AnyUserName'
        secret.callback_pass = 'SomeThing'
        secret.save()

        url = reverse('secret')

        data = {
            'secret_id': str(self.secret_id),
            'data': '123457',
            'data_nonce': ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(mock_request_post.call_count, 1)

        target_data = {
            'event': 'UPDATE_SECRET_SUCCESS',
            'secret_id': str(self.secret_id)
        }

        target_headers = {'content-type': 'application/json'}
        target_auth = (secret.callback_user, secret.callback_pass)

        mock_request_post.assert_any_call(secret.callback_url, data=target_data, headers=target_headers, auth=target_auth, timeout=5.0)
