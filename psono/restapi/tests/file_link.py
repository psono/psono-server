import json
import os
import binascii
import random
import string
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch

from django.urls import reverse

from rest_framework import status

from restapi import models
from restapi.utils import encrypt_with_db_secret

from .base import APITestCaseExtended


class FileLinkDeleteTests(APITestCaseExtended):
    """
    Tests for DELETE /file/link/ endpoint - deleting file links and ensuring proper file cleanup
    """

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "asd"
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
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce='3e7a12fcb7171c917005ef8110503ffbb85764163dbb567ef481e72a37f352a7',
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

    def test_delete_file_link_with_shard_file_soft_deletes(self):
        """
        Tests that deleting the last file_link for a shard-based file soft-deletes the file
        """

        # Create a file on shard
        file = models.File.objects.create(
            shard=self.shard1,
            file_repository=None,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create file link
        link_id = 'a0e98f85-6134-49e9-9bc1-3face1401bdc'
        file_link = models.File_Link.objects.create(
            link_id=link_id,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None
        )

        url = reverse('file_link')

        data = {
            'link_id': link_id,
            'file_ids': [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify file_link was deleted
        self.assertFalse(models.File_Link.objects.filter(link_id=link_id).exists())

        # Verify file was soft-deleted (delete_date set)
        file_after = models.File.objects.get(id=file.id)
        self.assertIsNotNone(file_after.delete_date)
        self.assertLessEqual(file_after.delete_date, timezone.now())

    @patch('restapi.utils.gcs_delete')
    def test_delete_file_link_with_gcs_file_repository_hard_deletes(self, mock_gcs_delete):
        """
        Tests that deleting the last file_link for a GCS file repository file hard-deletes
        the file and calls gcs_delete for each chunk
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

        # Create a file using GCS file repository
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=None,
            chunk_count=2,
            size=1024,
            user=self.test_user_obj,
        )

        # Create chunks
        chunk1 = models.File_Chunk.objects.create(
            file=file,
            hash_checksum='abcdef123456',
            position=0,
            size=512,
            user=self.test_user_obj,
        )
        chunk2 = models.File_Chunk.objects.create(
            file=file,
            hash_checksum='fedcba654321',
            position=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create file link
        link_id = 'a0e98f85-6134-49e9-9bc1-3face1401bdc'
        file_link = models.File_Link.objects.create(
            link_id=link_id,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None
        )

        url = reverse('file_link')

        data = {
            'link_id': link_id,
            'file_ids': [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify gcs_delete was called for each chunk
        self.assertEqual(mock_gcs_delete.call_count, 2)

        # Verify file_link was deleted
        self.assertFalse(models.File_Link.objects.filter(link_id=link_id).exists())

        # Verify file was hard-deleted
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch('restapi.utils.aws_delete')
    def test_delete_file_link_with_aws_s3_file_repository(self, mock_aws_delete):
        """
        Tests that deleting file_link with AWS S3 file repository calls aws_delete
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

        # Create a file
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create chunk
        chunk = models.File_Chunk.objects.create(
            file=file,
            hash_checksum='abcdef123456',
            position=0,
            size=512,
            user=self.test_user_obj,
        )

        # Create file link
        link_id = 'a0e98f85-6134-49e9-9bc1-3face1401bdc'
        file_link = models.File_Link.objects.create(
            link_id=link_id,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None
        )

        url = reverse('file_link')

        data = {
            'link_id': link_id,
            'file_ids': [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify aws_delete was called
        self.assertEqual(mock_aws_delete.call_count, 1)

        # Verify file was hard-deleted
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch('restapi.utils.azure_blob_delete')
    def test_delete_file_link_with_azure_blob_file_repository(self, mock_azure_delete):
        """
        Tests that deleting file_link with Azure Blob file repository calls azure_blob_delete
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

        # Create a file
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create chunk
        chunk = models.File_Chunk.objects.create(
            file=file,
            hash_checksum='abcdef123456',
            position=0,
            size=512,
            user=self.test_user_obj,
        )

        # Create file link
        link_id = 'a0e98f85-6134-49e9-9bc1-3face1401bdc'
        file_link = models.File_Link.objects.create(
            link_id=link_id,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None
        )

        url = reverse('file_link')

        data = {
            'link_id': link_id,
            'file_ids': [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify azure_blob_delete was called
        self.assertEqual(mock_azure_delete.call_count, 1)

        # Verify file was hard-deleted
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    def test_delete_file_link_preserves_file_with_remaining_links(self):
        """
        Tests that deleting a file_link does NOT delete the file if other links still exist
        """

        # Create a file on shard
        file = models.File.objects.create(
            shard=self.shard1,
            file_repository=None,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create TWO separate datastores to allow two file links
        test_datastore2_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type-2",
            description="my-description-2",
            data=b"67890",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        # Create TWO file links with different link_ids (unique constraint)
        link_id1 = 'a0e98f85-6134-49e9-9bc1-3face1401bdc'
        file_link1 = models.File_Link.objects.create(
            link_id=link_id1,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None
        )

        link_id2 = 'b0e98f85-6134-49e9-9bc1-3face1401bdc'
        file_link2 = models.File_Link.objects.create(
            link_id=link_id2,
            file_id=file.id,
            parent_datastore_id=test_datastore2_obj.id,
            parent_share_id=None
        )

        url = reverse('file_link')

        # Delete only the first link
        data = {
            'link_id': link_id1,
            'file_ids': [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify first file_link was deleted
        self.assertFalse(models.File_Link.objects.filter(link_id=link_id1).exists())

        # Verify second file_link still exists
        self.assertTrue(models.File_Link.objects.filter(link_id=link_id2).exists())

        # Verify file was NOT deleted (still has a link)
        self.assertTrue(models.File.objects.filter(id=file.id).exists())
        file_after = models.File.objects.get(id=file.id)
        self.assertIsNone(file_after.delete_date)

    def test_delete_file_link_checks_orphaned_files_correctly(self):
        """
        Tests that DELETE checks file_ids parameter correctly - only deletes truly orphaned files
        """

        # Create a file on shard
        file1 = models.File.objects.create(
            shard=self.shard1,
            file_repository=None,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create another file that will remain linked
        file2 = models.File.objects.create(
            shard=self.shard1,
            file_repository=None,
            secret=None,
            chunk_count=1,
            size=256,
            user=self.test_user_obj,
        )

        # Create file link for file1
        link_id1 = 'a0e98f85-6134-49e9-9bc1-3face1401bdc'
        file_link1 = models.File_Link.objects.create(
            link_id=link_id1,
            file_id=file1.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None
        )

        # Create file link for file2 (different link_id)
        link_id2 = 'b0e98f85-6134-49e9-9bc1-3face1401bdc'
        file_link2 = models.File_Link.objects.create(
            link_id=link_id2,
            file_id=file2.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None
        )

        url = reverse('file_link')

        # Delete link_id1, but pass BOTH file IDs
        # Only file1 should be deleted (orphaned), file2 should remain (still has link_id2)
        data = {
            'link_id': link_id1,
            'file_ids': [str(file1.id), str(file2.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify link1 was deleted
        self.assertFalse(models.File_Link.objects.filter(link_id=link_id1).exists())

        # Verify link2 still exists
        self.assertTrue(models.File_Link.objects.filter(link_id=link_id2).exists())

        # Verify file1 was soft-deleted (orphaned)
        file1_after = models.File.objects.get(id=file1.id)
        self.assertIsNotNone(file1_after.delete_date)

        # Verify file2 was NOT deleted (still has link)
        file2_after = models.File.objects.get(id=file2.id)
        self.assertIsNone(file2_after.delete_date)
