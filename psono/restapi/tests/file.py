import json
import os
import binascii
import random
import string
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

from django.urls import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status

from restapi import models

from .base import APITestCaseExtended

class FileTests(APITestCaseExtended):
    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "asd"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "abc"
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
            user_sauce='3e7a12fcb7171c917005ef8110503ffbb85764163dbb567ef481e72a37f352a7',
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
            user_sauce='f3c0a6788364ab164d574b655ac2a90b8124d3a20fd341c38a24566188390d01',
            is_email_active=True
        )

        self.shard1 = models.Fileserver_Shard.objects.create(
            title='Some Shard Title',
            description='Some Shard Description',
        )

        self.cluster1 = models.Fileserver_Cluster.objects.create(
            title='Some Fileserver Cluster Title',
            auth_public_key='abc',
            auth_private_key='abc',
            file_size_limit=0,
        )

        self.fileserver1 = models.Fileserver_Cluster_Members.objects.create(
            create_ip='127.0.0.1',
            fileserver_cluster=self.cluster1,
            key='abc',
            public_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            secret_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            url='https://fs01.example.com/fileserver',
            read=True,
            write=True,
            delete_capability=True,
            valid_till=timezone.now() + timedelta(seconds=30),
        )

        models.Fileserver_Cluster_Member_Shard_Link.objects.create(
            shard=self.shard1,
            member=self.fileserver1,
            read=True,
            write=True,
            delete_capability=True,
            ip_read_whitelist=json.dumps([]),
            ip_read_blacklist=json.dumps([]),
            ip_write_whitelist=json.dumps([]),
            ip_write_blacklist=json.dumps([]),
        )

        self.file = models.File.objects.create(
            shard=self.shard1,
            file_repository_id=None,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description="my-description",
            data=b"12345",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.file_link = models.File_Link.objects.create(
            link_id='0e98f859-6134-49e9-9bc1-3face1401bdc',
            file_id=self.file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None
        )


    def test_post(self):
        """
        Tests POST on file
        """

        url = reverse('file')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


    def test_post_unauthenticated(self):
        """
        Tests POST on file unauthenticated
        """

        url = reverse('file')

        data = {}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_put(self):
        """
        Tests PUT on file
        """

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'link_id': "b8866161-0b1f-4a8e-acde-07047313ec8f",
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('file_id', response.data)
        self.assertIn('file_transfer_id', response.data)
        self.assertIn('file_transfer_secret_key', response.data)
    def test_put_unauthorized(self):
        """
        Tests PUT on file with a user who doesn't own the datastore
        """

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'link_id': "b8866161-0b1f-4a8e-acde-07047313ec8f",
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    def test_put_without_parent_datastore_nor_share_id(self):
        """
        Tests PUT on file without a parent_datastore nor share id
        """

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'link_id': "b8866161-0b1f-4a8e-acde-07047313ec8f",
            #'parent_datastore_id': str(self.test_datastore_obj.id),
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    def test_put_without_shard_id(self):
        """
        Tests PUT on file without a shard id
        """

        url = reverse('file')

        data = {
            #'shard_id': self.shard1.id,
            'link_id': "b8866161-0b1f-4a8e-acde-07047313ec8f",
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_with_not_existing_shard_id(self):
        """
        Tests PUT on file with not existing shard id
        """

        url = reverse('file')

        data = {
            'shard_id': '829b2d27-0039-4e9e-a12c-b9799119bfe7',
            'link_id': "b8866161-0b1f-4a8e-acde-07047313ec8f",
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_put_unauthenticated(self):
        """
        Tests PUT on file unauthenticated
        """

        url = reverse('file')

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_delete(self):
        """
        Tests DELETE on file
        """

        url = reverse('file')

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_unauthenticated(self):
        """
        Tests DELETE on file
        """

        url = reverse('file')

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_read(self):
        """
        Tests GET on file
        """

        url = reverse('file', kwargs={'file_id': str(self.file.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('file_transfer_id', response.data)
        self.assertIn('file_transfer_secret_key', response.data)

    def test_read_unauthorized(self):
        """
        Tests GET on file with a user that isn't authorized to do that
        """

        url = reverse('file', kwargs={'file_id': str(self.file.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_file_that_is_marked_for_deletion(self):
        """
        Tests GET on file with a file that has already marked for deleted
        """

        self.file.delete_date = timezone.now() - timedelta(minutes=5)
        self.file.save()

        url = reverse('file', kwargs={'file_id': str(self.file.id)})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_with_file_id_that_doesnt_exist(self):
        """
        Tests GET on file with a file id that doesn't exist
        """

        url = reverse('file', kwargs={'file_id': '3efcd977-184d-4124-acb4-d5c50cdffc79'})

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_unauthenticated(self):
        """
        Tests GET on file unauthenticated
        """

        url = reverse('file', kwargs={'file_id': str(self.file.id)})

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
