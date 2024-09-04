from http.cookiejar import request_port

from django.urls import reverse
from django.conf import settings

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models

from uuid import uuid4
from mock import patch

import json
import random
import string
import binascii
import os


class BulkReadSecretTest(APITestCaseExtended):
    """
    Test to read multiple secret in a bulk request (POST)
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

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data= b"12345",
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
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

        self.test_share2_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
            data_nonce="12345"
        )

        self.test_user_share_right1_obj = models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user_obj.id,
            share_id=self.test_share2_obj.id,
            read=True,
            write=True,
            grant=True,
            accepted=True
        )


        self.test_secret_obj1 = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=b'12345',
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.secret_link_obj1 = models.Secret_Link.objects.create(
            link_id = str(uuid4()),
            secret_id = self.test_secret_obj1.id,
            parent_datastore_id = self.test_datastore_obj.id,
            parent_share_id = None
        )


        self.test_secret_obj2 = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=b'12345',
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.secret_link_obj2 = models.Secret_Link.objects.create(
            link_id = str(uuid4()),
            secret_id = self.test_secret_obj2.id,
            parent_datastore_id = self.test_datastore_obj.id,
            parent_share_id = None
        )


        self.test_secret_obj3 = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=b'12345',
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.secret_link_obj3 = models.Secret_Link.objects.create(
            link_id = str(uuid4()),
            secret_id = self.test_secret_obj3.id,
            parent_datastore_id = self.test_datastore_obj.id,
            parent_share_id = None
        )


        self.test_secret_obj4 = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=b'12345',
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.secret_link_obj4 = models.Secret_Link.objects.create(
            link_id = str(uuid4()),
            secret_id = self.test_secret_obj4.id,
            parent_datastore_id = None,
            parent_share_id = self.test_share1_obj.id
        )


        self.test_secret_obj5 = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data=b'12345',
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.secret_link_obj5 = models.Secret_Link.objects.create(
            link_id = str(uuid4()),
            secret_id = self.test_secret_obj5.id,
            parent_datastore_id = None,
            parent_share_id = self.test_share2_obj.id
        )


    def test_read_secret_in_datastore(self):
        """
        Tests to read a secret successfully in datastore
        """

        url = reverse('bulk_secret_read')

        data = {
            'secret_ids': [
                str(self.test_secret_obj1.id),
                str(self.test_secret_obj2.id),
            ],
        }

        self.client.force_authenticate(user=self.test_user_obj)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = json.loads(response.content)

        self.assertTrue('secrets' in response_data)
        self.assertEqual(len(response_data['secrets']), 2)

        self.assertIn(str(self.test_secret_obj1.id), [s['id'] for s in response_data['secrets']])
        self.assertIn(str(self.test_secret_obj2.id), [s['id'] for s in response_data['secrets']])


    def test_read_secret_unauthenticated(self):
        """
        Tests to read unauhtenticated
        """

        url = reverse('bulk_secret_read')

        data = {
            'secret_ids': [
                str(self.test_secret_obj1.id),
                str(self.test_secret_obj2.id),
            ],
        }

        #self.client.force_authenticate(user=self.test_user_obj)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_read_secrets_no_permission(self):
        """
        Tests to read secrets where the user is missing permissions
        """

        url = reverse('bulk_secret_read')

        self.secret_link_obj1.delete()

        data = {
            'secret_ids': [
                str(self.test_secret_obj1.id),
                str(self.test_secret_obj2.id),
            ],
        }

        self.client.force_authenticate(user=self.test_user_obj)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = json.loads(response.content)

        self.assertTrue('secrets' in response_data)
        self.assertEqual(len(response_data['secrets']), 1)
        self.assertIn(str(self.test_secret_obj2.id), [s['id'] for s in response_data['secrets']])


    def test_read_empty_secrets(self):
        """
        Tests to read bulk secrets without secrets
        """

        url = reverse('bulk_secret_read')

        self.secret_link_obj1.delete()

        data = {
            'secret_ids': [
                # str(self.test_secret_obj1.id),
                # str(self.test_secret_obj2.id),
            ],
        }

        self.client.force_authenticate(user=self.test_user_obj)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response_data = json.loads(response.content)

        self.assertTrue('secret_ids' in response_data)
        self.assertEqual(response_data['secret_ids'][0], 'Ensure this field has at least 1 elements.')


    def test_read_secrets_not_exist(self):
        """
        Tests to read secrets that don't exist
        """

        url = reverse('bulk_secret_read')

        self.secret_link_obj1.delete()

        data = {
            'secret_ids': [
                "67f2e33b-186e-465f-8e0f-17c8cc0f4144",
                str(self.test_secret_obj2.id),
            ],
        }

        self.client.force_authenticate(user=self.test_user_obj)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = json.loads(response.content)

        self.assertTrue('secrets' in response_data)
        self.assertEqual(len(response_data['secrets']), 1)
        self.assertIn(str(self.test_secret_obj2.id), [s['id'] for s in response_data['secrets']])


    def test_read_secret_in_shares(self):
        """
        Tests to read secrets successfully in shares
        """

        url = reverse('bulk_secret_read')

        data = {
            'secret_ids': [
                str(self.test_secret_obj4.id),
                str(self.test_secret_obj5.id),
            ],
        }

        self.client.force_authenticate(user=self.test_user_obj)

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response_data = json.loads(response.content)

        self.assertTrue('secrets' in response_data)
        self.assertEqual(len(response_data['secrets']), 2)

        self.assertIn(str(self.test_secret_obj4.id), [s['id'] for s in response_data['secrets']])
        self.assertIn(str(self.test_secret_obj5.id), [s['id'] for s in response_data['secrets']])


    def test_db_queries(self):
        """
        Tests to make sure db query count is linear and requires always 4 queries no matter how many secrets one request
        """

        query_count = 4

        url = reverse('bulk_secret_read')

        data = {
            'secret_ids': [],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        with self.assertNumQueries(0):
            self.client.post(url, data)

        data = {
            'secret_ids': [
                str(self.test_secret_obj1.id),
            ],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        with self.assertNumQueries(query_count):
            self.client.post(url, data)

        data = {
            'secret_ids': [
                str(self.test_secret_obj1.id),
                str(self.test_secret_obj2.id),
                str(self.test_secret_obj3.id),
            ],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        with self.assertNumQueries(query_count):
            self.client.post(url, data)

        data = {
            'secret_ids': [
                str(self.test_secret_obj1.id),
                str(self.test_secret_obj2.id),
                str(self.test_secret_obj3.id),
                str(self.test_secret_obj4.id), # This secret resides in a share and should cause 2 extra DB query
            ],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        with self.assertNumQueries(query_count + 2):
            self.client.post(url, data)

        data = {
            'secret_ids': [
                str(self.test_secret_obj1.id),
                str(self.test_secret_obj2.id),
                str(self.test_secret_obj3.id),
                str(self.test_secret_obj4.id), # This secret resides in a share and should cause 1 extra DB query
                str(self.test_secret_obj5.id), # This secret resides in another share
            ],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        with self.assertNumQueries(query_count + 2):
            self.client.post(url, data)


    def test_get_bulk_secret_read(self):
        """
        Tests GET method on bulk_secret_read
        """

        url = reverse('bulk_secret_read')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_get_bulk_secret_read_unauthenticated(self):
        """
        Tests GET method on bulk_secret_read
        """

        url = reverse('bulk_secret_read')

        data = {}

        #self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_put_bulk_secret_read(self):
        """
        Tests PUT method on bulk_secret_read
        """

        url = reverse('bulk_secret_read')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_put_bulk_secret_read_unauthenticated(self):
        """
        Tests PUT method on bulk_secret_read
        """

        url = reverse('bulk_secret_read')

        data = {}

        #self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_delete_bulk_secret_read(self):
        """
        Tests DELETE method on bulk_secret_read
        """

        url = reverse('bulk_secret_read')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_delete_bulk_secret_read_unauthenticated(self):
        """
        Tests DELETE method on bulk_secret_read
        """

        url = reverse('bulk_secret_read')

        data = {}

        #self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


