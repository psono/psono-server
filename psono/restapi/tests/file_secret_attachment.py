import json
import os
import binascii
import random
import string
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch, MagicMock

from django.urls import reverse

from rest_framework import status

from restapi import models
from restapi.utils import encrypt_with_db_secret

from .base import APITestCaseExtended


class FileSecretAttachmentTests(APITestCaseExtended):
    """
    Tests for file attachments to secrets
    """

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
            authkey="abc",
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
            authkey="abc",
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

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description="my-description",
            data=b"12345",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        # Create a secret owned by test_user_obj
        self.secret1 = models.Secret.objects.create(
            user=self.test_user_obj,
            data=b"secret-data",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type='password',
        )

        self.secret_link1 = models.Secret_Link.objects.create(
            link_id='a0e98f85-6134-49e9-9bc1-3face1401bdc',
            secret_id=self.secret1.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None
        )

        # Create a secret owned by test_user2_obj (user without access)
        self.test_datastore2_obj = models.Data_Store.objects.create(
            user_id=self.test_user2_obj.id,
            type="my-type",
            description="my-description",
            data=b"12345",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.secret2 = models.Secret.objects.create(
            user=self.test_user2_obj,
            data=b"secret-data-2",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type='password',
        )

        self.secret_link2 = models.Secret_Link.objects.create(
            link_id='b0e98f85-6134-49e9-9bc1-3face1401bdc',
            secret_id=self.secret2.id,
            parent_datastore_id=self.test_datastore2_obj.id,
            parent_share_id=None
        )

    def test_create_file_with_parent_secret_id(self):
        """
        Tests PUT on file with parent_secret_id
        """

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'parent_secret_id': str(self.secret1.id),
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        if response.status_code != status.HTTP_201_CREATED:
            print(f"Error response: {response.data}")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('file_id', response.data)
        self.assertIn('file_transfer_id', response.data)
        self.assertIn('file_transfer_secret_key', response.data)

        # Verify the file was created with secret_id set
        file = models.File.objects.get(id=response.data['file_id'])
        self.assertEqual(str(file.secret_id), str(self.secret1.id))

        # Verify no File_Link was created
        file_link_count = models.File_Link.objects.filter(file_id=file.id).count()
        self.assertEqual(file_link_count, 0)

    def test_create_file_with_parent_secret_id_no_permission(self):
        """
        Tests PUT on file with parent_secret_id where user has no permission on secret
        """

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'parent_secret_id': str(self.secret2.id),  # Secret owned by user2
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('NO_PERMISSION_OR_NOT_EXIST', str(response.data))

    def test_create_file_with_both_parent_secret_and_link_id(self):
        """
        Tests PUT on file with both parent_secret_id and link_id (should fail)
        """

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'parent_secret_id': str(self.secret1.id),
            'link_id': "b8866161-0b1f-4a8e-acde-07047313ec8f",
            'parent_datastore_id': str(self.test_datastore_obj.id),
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('EITHER_PARENT_SECRET_OR_LINK_NOT_BOTH', str(response.data))

    def test_create_file_without_parent_secret_or_link_id(self):
        """
        Tests PUT on file without parent_secret_id or link_id (should fail)
        """

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('EITHER_PARENT_SECRET_OR_LINK_NEED_TO_BE_DEFINED', str(response.data))

    def test_create_file_with_nonexistent_parent_secret_id(self):
        """
        Tests PUT on file with a non-existent parent_secret_id
        """

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'parent_secret_id': '00000000-0000-0000-0000-000000000000',
            'chunk_count': 1,
            'size': 512,
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('NO_PERMISSION_OR_NOT_EXIST', str(response.data))

    def test_delete_secret_cascades_to_attached_file_shard(self):
        """
        Tests that deleting a secret also deletes attached files (shard storage - soft delete)
        """

        # Create a file attached to secret1
        file = models.File.objects.create(
            shard=self.shard1,
            file_repository_id=None,
            secret=self.secret1,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        file_id = file.id

        # Verify file exists
        self.assertTrue(models.File.objects.filter(id=file_id).exists())

        # Delete the secret
        self.secret1.delete()

        # Verify file was soft-deleted (delete_date set) for shard files
        # Note: For shard files, we use soft delete
        file_exists = models.File.objects.filter(id=file_id).exists()
        if file_exists:
            # If still exists, should have delete_date set
            file = models.File.objects.get(id=file_id)
            self.assertIsNotNone(file.delete_date)
        else:
            # If hard deleted, that's also acceptable
            self.assertFalse(models.File.objects.filter(id=file_id).exists())

    def test_read_file_attached_to_secret_with_permission(self):
        """
        Tests GET on file attached to a secret where user has permission
        """

        # Create a file attached to secret1
        file = models.File.objects.create(
            shard=self.shard1,
            file_repository_id=None,
            secret=self.secret1,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        url = reverse('file', kwargs={'file_id': str(file.id)})

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('file_transfer_id', response.data)
        self.assertIn('file_transfer_secret_key', response.data)

    def test_read_file_attached_to_secret_without_permission(self):
        """
        Tests GET on file attached to a secret where user has no permission
        """

        # Create a file attached to secret2 (owned by user2)
        file = models.File.objects.create(
            shard=self.shard1,
            file_repository_id=None,
            secret=self.secret2,
            chunk_count=1,
            size=50,
            user=self.test_user2_obj,
        )

        url = reverse('file', kwargs={'file_id': str(file.id)})

        # Try to access as user1 (no permission)
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('NO_PERMISSION_OR_NOT_EXIST', str(response.data))

    def test_file_attached_to_secret_has_no_file_links(self):
        """
        Tests that files attached to secrets do not have File_Link entries
        """

        # Create a file attached to secret1
        file = models.File.objects.create(
            shard=self.shard1,
            file_repository_id=None,
            secret=self.secret1,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        # Verify no File_Link exists for this file
        file_link_count = models.File_Link.objects.filter(file_id=file.id).count()
        self.assertEqual(file_link_count, 0)

    def test_permission_inheritance_from_secret(self):
        """
        Tests that file permissions are inherited from parent secret
        """

        from restapi.utils import user_has_rights_on_file

        # Create a file attached to secret1
        file = models.File.objects.create(
            shard=self.shard1,
            file_repository_id=None,
            secret=self.secret1,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        # User1 should have access (owns the secret)
        has_access = user_has_rights_on_file(str(self.test_user_obj.id), file, read=True)
        self.assertTrue(has_access)

        # User2 should not have access (doesn't own the secret)
        has_access = user_has_rights_on_file(str(self.test_user2_obj.id), file, read=True)
        self.assertFalse(has_access)

    def test_create_file_with_parent_secret_id_and_share_access(self):
        """
        Tests that a user with write access to a shared secret can attach files
        """

        # Create a share and give user2 write access to secret1
        share = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"share-data",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        models.User_Share_Right.objects.create(
            creator_id=self.test_user_obj.id,
            user_id=self.test_user2_obj.id,
            share_id=share.id,
            read=True,
            write=True,
            grant=False,
            accepted=True
        )

        # Move secret1 to the share
        models.Secret_Link.objects.filter(secret_id=self.secret1.id).delete()
        models.Secret_Link.objects.create(
            link_id='c0e98f85-6134-49e9-9bc1-3face1401bdc',
            secret_id=self.secret1.id,
            parent_share_id=share.id,
            parent_datastore_id=None
        )

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'parent_secret_id': str(self.secret1.id),
            'chunk_count': 1,
            'size': 512,
        }

        # User2 should be able to attach a file (has write access to shared secret)
        self.client.force_authenticate(user=self.test_user2_obj)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('file_id', response.data)

        # Verify the file was created with secret_id set
        file = models.File.objects.get(id=response.data['file_id'])
        self.assertEqual(str(file.secret_id), str(self.secret1.id))

    def test_unauthenticated_create_file_with_parent_secret_id(self):
        """
        Tests PUT on file with parent_secret_id without authentication
        """

        url = reverse('file')

        data = {
            'shard_id': self.shard1.id,
            'parent_secret_id': str(self.secret1.id),
            'chunk_count': 1,
            'size': 512,
        }

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('restapi.utils.gcs_delete')
    def test_delete_secret_cascades_to_gcs_file_repository(self, mock_gcs_delete):
        """
        Tests that deleting a secret with GCS file repository attachment calls gcs_delete
        """

        # Create a GCS file repository
        file_repository_data = {
            'gcp_cloud_storage_bucket': 'test-bucket',
            'gcp_cloud_storage_json_key': '{"key": "value"}',
        }
        file_repository = models.File_Repository.objects.create(
            title='Test GCS Repository',
            type='gcp_cloud_storage',
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file attached to secret1 using GCS file repository
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=self.secret1,
            chunk_count=2,
            size=100,
            user=self.test_user_obj,
        )

        # Create file chunks
        chunk1 = models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum='hash1',
            position=0,
            size=50,
        )

        chunk2 = models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum='hash2',
            position=1,
            size=50,
        )

        # Delete the secret
        self.secret1.delete()

        # Verify gcs_delete was called for each chunk
        self.assertEqual(mock_gcs_delete.call_count, 2)

        # Verify the calls were made with correct parameters
        calls = mock_gcs_delete.call_args_list
        self.assertEqual(calls[0][0][0], 'test-bucket')  # bucket
        self.assertEqual(calls[0][0][1], '{"key": "value"}')  # json_key
        self.assertEqual(calls[0][0][2], 'hash1')  # hash_checksum

        self.assertEqual(calls[1][0][0], 'test-bucket')
        self.assertEqual(calls[1][0][1], '{"key": "value"}')
        self.assertEqual(calls[1][0][2], 'hash2')

        # Verify file was deleted from database
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch('restapi.utils.aws_delete')
    def test_delete_secret_cascades_to_aws_s3_file_repository(self, mock_aws_delete):
        """
        Tests that deleting a secret with AWS S3 file repository attachment calls aws_delete
        """

        # Create an AWS S3 file repository
        file_repository_data = {
            'aws_s3_bucket': 'test-aws-bucket',
            'aws_s3_region': 'us-east-1',
            'aws_s3_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'aws_s3_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        }
        file_repository = models.File_Repository.objects.create(
            title='Test AWS S3 Repository',
            type='aws_s3',
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file attached to secret1
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=self.secret1,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        # Create file chunk
        chunk = models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum='aws-hash-1',
            position=0,
            size=50,
        )

        # Delete the secret
        self.secret1.delete()

        # Verify aws_delete was called
        self.assertEqual(mock_aws_delete.call_count, 1)

        # Verify the call parameters
        call_args = mock_aws_delete.call_args[0]
        self.assertEqual(call_args[0], 'test-aws-bucket')
        self.assertEqual(call_args[1], 'us-east-1')
        self.assertEqual(call_args[2], 'AKIAIOSFODNN7EXAMPLE')
        self.assertEqual(call_args[3], 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
        self.assertEqual(call_args[4], 'aws-hash-1')

        # Verify file was deleted from database
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch('restapi.utils.azure_blob_delete')
    def test_delete_secret_cascades_to_azure_blob_file_repository(self, mock_azure_delete):
        """
        Tests that deleting a secret with Azure Blob file repository attachment calls azure_blob_delete
        """

        # Create an Azure Blob file repository
        file_repository_data = {
            'azure_blob_storage_account_name': 'testaccount',
            'azure_blob_storage_account_primary_key': 'test-primary-key',
            'azure_blob_storage_account_container_name': 'test-container',
        }
        file_repository = models.File_Repository.objects.create(
            title='Test Azure Blob Repository',
            type='azure_blob',
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file attached to secret1
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=self.secret1,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        # Create file chunk
        chunk = models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum='azure-hash-1',
            position=0,
            size=50,
        )

        # Delete the secret
        self.secret1.delete()

        # Verify azure_blob_delete was called
        self.assertEqual(mock_azure_delete.call_count, 1)

        # Verify the call parameters
        call_args = mock_azure_delete.call_args[0]
        self.assertEqual(call_args[0], 'testaccount')
        self.assertEqual(call_args[1], 'test-primary-key')
        self.assertEqual(call_args[2], 'test-container')
        self.assertEqual(call_args[3], 'azure-hash-1')

        # Verify file was deleted from database
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch('restapi.utils.do_delete')
    def test_delete_secret_cascades_to_do_spaces_file_repository(self, mock_do_delete):
        """
        Tests that deleting a secret with DigitalOcean Spaces file repository attachment calls do_delete
        """

        # Create a DO Spaces file repository
        file_repository_data = {
            'do_space': 'test-space',
            'do_region': 'nyc3',
            'do_key': 'DO-KEY',
            'do_secret': 'DO-SECRET',
        }
        file_repository = models.File_Repository.objects.create(
            title='Test DO Spaces Repository',
            type='do_spaces',
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file attached to secret1
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=self.secret1,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        # Create file chunk
        chunk = models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum='do-hash-1',
            position=0,
            size=50,
        )

        # Delete the secret
        self.secret1.delete()

        # Verify do_delete was called
        self.assertEqual(mock_do_delete.call_count, 1)

        # Verify the call parameters
        call_args = mock_do_delete.call_args[0]
        self.assertEqual(call_args[0], 'test-space')
        self.assertEqual(call_args[1], 'nyc3')
        self.assertEqual(call_args[2], 'DO-KEY')
        self.assertEqual(call_args[3], 'DO-SECRET')
        self.assertEqual(call_args[4], 'do-hash-1')

        # Verify file was deleted from database
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch('restapi.utils.backblaze_delete')
    def test_delete_secret_cascades_to_backblaze_file_repository(self, mock_backblaze_delete):
        """
        Tests that deleting a secret with Backblaze file repository attachment calls backblaze_delete
        """

        # Create a Backblaze file repository
        file_repository_data = {
            'backblaze_bucket': 'test-b2-bucket',
            'backblaze_region': 'us-west-002',
            'backblaze_access_key_id': 'B2-KEY-ID',
            'backblaze_secret_access_key': 'B2-SECRET',
        }
        file_repository = models.File_Repository.objects.create(
            title='Test Backblaze Repository',
            type='backblaze',
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file attached to secret1
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=self.secret1,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        # Create file chunk
        chunk = models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum='b2-hash-1',
            position=0,
            size=50,
        )

        # Delete the secret
        self.secret1.delete()

        # Verify backblaze_delete was called
        self.assertEqual(mock_backblaze_delete.call_count, 1)

        # Verify the call parameters
        call_args = mock_backblaze_delete.call_args[0]
        self.assertEqual(call_args[0], 'test-b2-bucket')
        self.assertEqual(call_args[1], 'us-west-002')
        self.assertEqual(call_args[2], 'B2-KEY-ID')
        self.assertEqual(call_args[3], 'B2-SECRET')
        self.assertEqual(call_args[4], 'b2-hash-1')

        # Verify file was deleted from database
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch('restapi.utils.s3_delete')
    @patch('restapi.utils.is_allowed_other_s3_endpoint_url')
    def test_delete_secret_cascades_to_other_s3_file_repository(self, mock_is_allowed, mock_s3_delete):
        """
        Tests that deleting a secret with other S3-compatible file repository attachment calls s3_delete
        """

        # Mock the URL validation to return True
        mock_is_allowed.return_value = True

        # Create an other S3 file repository
        file_repository_data = {
            'other_s3_bucket': 'test-s3-bucket',
            'other_s3_region': 'us-west-1',
            'other_s3_access_key_id': 'S3-KEY',
            'other_s3_secret_access_key': 'S3-SECRET',
            'other_s3_endpoint_url': 'https://s3.example.com',
        }
        file_repository = models.File_Repository.objects.create(
            title='Test Other S3 Repository',
            type='other_s3',
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file attached to secret1
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=self.secret1,
            chunk_count=1,
            size=50,
            user=self.test_user_obj,
        )

        # Create file chunk
        chunk = models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum='s3-hash-1',
            position=0,
            size=50,
        )

        # Delete the secret
        self.secret1.delete()

        # Verify is_allowed_other_s3_endpoint_url was called
        mock_is_allowed.assert_called_once_with('https://s3.example.com')

        # Verify s3_delete was called
        self.assertEqual(mock_s3_delete.call_count, 1)

        # Verify the call parameters
        call_args = mock_s3_delete.call_args[0]
        self.assertEqual(call_args[0], 'test-s3-bucket')
        self.assertEqual(call_args[1], 'us-west-1')
        self.assertEqual(call_args[2], 'S3-KEY')
        self.assertEqual(call_args[3], 'S3-SECRET')
        self.assertEqual(call_args[4], 's3-hash-1')

        # Verify endpoint_url was passed as keyword argument
        call_kwargs = mock_s3_delete.call_args[1]
        self.assertEqual(call_kwargs['endpoint_url'], 'https://s3.example.com')

        # Verify file was deleted from database
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch('restapi.utils.gcs_delete')
    def test_delete_secret_with_multiple_chunks_calls_delete_for_each(self, mock_gcs_delete):
        """
        Tests that deleting a secret with a file with multiple chunks calls delete for each chunk
        """

        # Create a GCS file repository
        file_repository_data = {
            'gcp_cloud_storage_bucket': 'test-bucket',
            'gcp_cloud_storage_json_key': '{"key": "value"}',
        }
        file_repository = models.File_Repository.objects.create(
            title='Test GCS Repository',
            type='gcp_cloud_storage',
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file with 5 chunks
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=self.secret1,
            chunk_count=5,
            size=250,
            user=self.test_user_obj,
        )

        # Create 5 file chunks
        for i in range(5):
            models.File_Chunk.objects.create(
                user=self.test_user_obj,
                file=file,
                hash_checksum=f'hash-{i}',
                position=i,
                size=50,
            )

        # Delete the secret
        self.secret1.delete()

        # Verify gcs_delete was called 5 times (once per chunk)
        self.assertEqual(mock_gcs_delete.call_count, 5)

        # Verify each chunk hash was passed
        chunk_hashes = [call[0][2] for call in mock_gcs_delete.call_args_list]
        self.assertEqual(sorted(chunk_hashes), ['hash-0', 'hash-1', 'hash-2', 'hash-3', 'hash-4'])

    @patch('restapi.utils.gcs_delete')
    def test_delete_secret_continues_on_chunk_delete_failure(self, mock_gcs_delete):
        """
        Tests that secret deletion continues even if individual chunk deletion fails
        """

        # Mock gcs_delete to raise exception on first call, succeed on second
        mock_gcs_delete.side_effect = [Exception("Delete failed"), None]

        # Create a GCS file repository
        file_repository_data = {
            'gcp_cloud_storage_bucket': 'test-bucket',
            'gcp_cloud_storage_json_key': '{"key": "value"}',
        }
        file_repository = models.File_Repository.objects.create(
            title='Test GCS Repository',
            type='gcp_cloud_storage',
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file with 2 chunks
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=self.secret1,
            chunk_count=2,
            size=100,
            user=self.test_user_obj,
        )

        models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum='hash-1',
            position=0,
            size=50,
        )

        models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum='hash-2',
            position=1,
            size=50,
        )

        # Delete the secret - should not raise exception
        self.secret1.delete()

        # Verify gcs_delete was called twice (even though first failed)
        self.assertEqual(mock_gcs_delete.call_count, 2)

        # Verify file was still deleted from database
        self.assertFalse(models.File.objects.filter(id=file.id).exists())
