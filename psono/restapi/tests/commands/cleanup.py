from django.core.management import call_command
from django.test import TestCase
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch

from restapi import models
from restapi.utils import encrypt_with_db_secret

import binascii
import random
import string
import os
import json
from io import StringIO

import hashlib

class CommandCleartokenTestCase(TestCase):
    #
    def setUp(self):
        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678'
        self.test_public_key = binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode()
        self.test_private_key = binascii.hexlify(os.urandom(settings.USER_PRIVATE_KEY_LENGTH_BYTES)).decode()
        self.test_private_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_secret_key = binascii.hexlify(os.urandom(settings.USER_SECRET_KEY_LENGTH_BYTES)).decode()
        self.test_secret_key_nonce = binascii.hexlify(os.urandom(settings.NONCE_LENGTH_BYTES)).decode()
        self.test_user_sauce = 'd22f5797cfd438f212bb0830da488f0555487697ad4041bbcbf5b08bc297e117'
        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
            is_email_active=True
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description= "my-description",
            data='12345'.encode(),
            data_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key= ''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce= ''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

        self.test_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data='12345'.encode(),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        self.secret_link_obj = models.Secret_Link.objects.create(
            link_id = '0493017f-47b0-446e-9a41-6533721ade71',
            secret_id = self.test_secret_obj.id,
            parent_datastore_id = self.test_datastore_obj.id,
            parent_share_id = None
        )


    def test_expired_token(self):

        # Lets put one tokens validity into the future, and one into the past
        self.token = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        models.Token.objects.create(
            key= hashlib.sha512(self.token.encode()).hexdigest(),
            user=self.test_user_obj,
            valid_till=timezone.now() + timedelta(seconds=10)
        )

        self.token2 = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        models.Token.objects.create(
            key= hashlib.sha512(self.token2.encode()).hexdigest(),
            user=self.test_user_obj,
            valid_till = timezone.now() - timedelta(seconds=10)
        )

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        self.assertEqual(models.Token.objects.count(), 1)

    def test_expired_link_shares(self):
        link_share1 = models.Link_Share.objects.create(
            user=self.test_user_obj,
            secret=self.test_secret_obj,
            file_id=None,
            allowed_reads=True,
            public_title='A public title',
            node=b'kbixmnfhbzmelpujlulqtlulvcvptmauciygeyoipmlehhyuaizhqzzrtjhemdoi',
            node_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            passphrase=None,
            valid_till=timezone.now() + timedelta(seconds=10),
        )

        # The expired link share that should be deleted
        link_share2 = models.Link_Share.objects.create(
            user=self.test_user_obj,
            secret=self.test_secret_obj,
            file_id=None,
            allowed_reads=True,
            public_title='A public title',
            node=b'kbixmnfhbzmelpujlulqtlulvcvptmauciygeyoipmlehhyuaizhqzzrtjhemdoi',
            node_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            passphrase=None,
            valid_till=timezone.now() - timedelta(seconds=10),
        )

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        self.assertEqual(models.Link_Share.objects.count(), 1)
        self.assertTrue(models.Link_Share.objects.filter(pk=link_share1.id).exists())
        self.assertFalse(models.Link_Share.objects.filter(pk=link_share2.id).exists())

    def test_inaccessible_shares(self):
        share_link_id = '1515a857-0bb9-46e0-9a84-97787b3d8ec6'
        test_share1_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
            data_nonce="12345",
        )
        test_share1_obj.create_date=timezone.now() - timedelta(days=30)
        test_share1_obj.save()

        models.Share_Tree.objects.create(
            share_id=test_share1_obj.id,
            parent_datastore_id=self.test_datastore_obj.id,
            path=str(share_link_id).replace("-", "")
        )

        # share with missing share tree entry
        test_share2_obj = models.Share.objects.create(
            user_id=self.test_user_obj.id,
            data=b"my-data",
            data_nonce="12345",
        )
        test_share2_obj.create_date=timezone.now() - timedelta(days=30)
        test_share2_obj.save()

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        self.assertEqual(models.Share.objects.count(), 1)
        self.assertTrue(models.Share.objects.filter(pk=test_share1_obj.id).exists())
        self.assertFalse(models.Share.objects.filter(pk=test_share2_obj.id).exists())

    def test_inaccessible_secrets(self):

        inaccessible_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data='12345'.encode(),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        self.assertEqual(models.Secret.objects.count(), 1)
        self.assertTrue(models.Secret.objects.filter(pk=self.test_secret_obj.id).exists())
        self.assertFalse(models.Secret.objects.filter(pk=inaccessible_secret_obj.id).exists())

    @patch('restapi.utils.gcs_delete')
    def test_inaccessible_secret_with_gcs_file_repository_cleanup(self, mock_gcs_delete):
        """
        Tests that cleanup command properly deletes files in GCS file repository
        when deleting orphaned secrets
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

        # Create an orphaned secret (no Secret_Link)
        inaccessible_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data='12345'.encode(),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        # Create a file attached to the orphaned secret using GCS file repository
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=inaccessible_secret_obj,
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

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        # Verify gcs_delete was called for each chunk
        self.assertEqual(mock_gcs_delete.call_count, 2)

        # Verify secret was deleted
        self.assertFalse(models.Secret.objects.filter(pk=inaccessible_secret_obj.id).exists())

        # Verify file was deleted
        self.assertFalse(models.File.objects.filter(pk=file.id).exists())

    def test_inaccessible_secret_with_shard_file_cleanup(self):
        """
        Tests that cleanup command properly soft-deletes files on shards
        when deleting orphaned secrets
        """

        # Create a shard
        shard = models.Fileserver_Shard.objects.create(
            title='Test Shard',
            description='Test Shard Description',
        )

        # Create an orphaned secret (no Secret_Link)
        inaccessible_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data='12345'.encode(),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        # Create a file attached to the orphaned secret using shard
        file = models.File.objects.create(
            shard=shard,
            file_repository=None,
            secret=inaccessible_secret_obj,
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

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        # Verify secret was deleted
        self.assertFalse(models.Secret.objects.filter(pk=inaccessible_secret_obj.id).exists())

        # Verify file was soft-deleted (delete_date set)
        file_after = models.File.objects.get(pk=file.id)
        self.assertIsNotNone(file_after.delete_date)
        self.assertLessEqual(file_after.delete_date, timezone.now())

    @patch('restapi.utils.aws_delete')
    def test_inaccessible_secret_with_aws_s3_file_repository_cleanup(self, mock_aws_delete):
        """
        Tests that cleanup command properly deletes files in AWS S3 file repository
        when deleting orphaned secrets
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

        # Create an orphaned secret (no Secret_Link)
        inaccessible_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data='12345'.encode(),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        # Create a file attached to the orphaned secret
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=inaccessible_secret_obj,
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

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        # Verify aws_delete was called
        self.assertEqual(mock_aws_delete.call_count, 1)

        # Verify secret was deleted
        self.assertFalse(models.Secret.objects.filter(pk=inaccessible_secret_obj.id).exists())

        # Verify file was deleted
        self.assertFalse(models.File.objects.filter(pk=file.id).exists())

    @patch('restapi.utils.azure_blob_delete')
    def test_inaccessible_secret_with_azure_blob_file_repository_cleanup(self, mock_azure_delete):
        """
        Tests that cleanup command properly deletes files in Azure Blob file repository
        when deleting orphaned secrets
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

        # Create an orphaned secret (no Secret_Link)
        inaccessible_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data='12345'.encode(),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        # Create a file attached to the orphaned secret
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=inaccessible_secret_obj,
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

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        # Verify azure_blob_delete was called
        self.assertEqual(mock_azure_delete.call_count, 1)

        # Verify secret was deleted
        self.assertFalse(models.Secret.objects.filter(pk=inaccessible_secret_obj.id).exists())

        # Verify file was deleted
        self.assertFalse(models.File.objects.filter(pk=file.id).exists())

    def test_inaccessible_secret_with_multiple_files_cleanup(self):
        """
        Tests that cleanup command properly deletes multiple files attached to same orphaned secret
        """

        # Create a shard
        shard = models.Fileserver_Shard.objects.create(
            title='Test Shard',
            description='Test Shard Description',
        )

        # Create an orphaned secret (no Secret_Link)
        inaccessible_secret_obj = models.Secret.objects.create(
            user_id=self.test_user_obj.id,
            data='12345'.encode(),
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            type="dummy"
        )

        # Create multiple files attached to the orphaned secret
        file1 = models.File.objects.create(
            shard=shard,
            file_repository=None,
            secret=inaccessible_secret_obj,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        file2 = models.File.objects.create(
            shard=shard,
            file_repository=None,
            secret=inaccessible_secret_obj,
            chunk_count=1,
            size=256,
            user=self.test_user_obj,
        )

        file3 = models.File.objects.create(
            shard=shard,
            file_repository=None,
            secret=inaccessible_secret_obj,
            chunk_count=1,
            size=128,
            user=self.test_user_obj,
        )

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        # Verify secret was deleted
        self.assertFalse(models.Secret.objects.filter(pk=inaccessible_secret_obj.id).exists())

        # Verify all files were soft-deleted
        file1_after = models.File.objects.get(pk=file1.id)
        self.assertIsNotNone(file1_after.delete_date)

        file2_after = models.File.objects.get(pk=file2.id)
        self.assertIsNotNone(file2_after.delete_date)

        file3_after = models.File.objects.get(pk=file3.id)
        self.assertIsNotNone(file3_after.delete_date)

    def test_accessible_secret_with_file_not_deleted(self):
        """
        Tests that cleanup command does NOT delete files attached to secrets with valid links
        """

        # Create a shard
        shard = models.Fileserver_Shard.objects.create(
            title='Test Shard',
            description='Test Shard Description',
        )

        # Create a file attached to the accessible secret (has Secret_Link)
        file = models.File.objects.create(
            shard=shard,
            file_repository=None,
            secret=self.test_secret_obj,  # This secret has a valid Secret_Link from setUp
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        args = []
        opts = {}

        out = StringIO()
        call_command('cleanup', stdout=out, *args, **opts)

        # Verify secret was NOT deleted (has valid link)
        self.assertTrue(models.Secret.objects.filter(pk=self.test_secret_obj.id).exists())

        # Verify file was NOT deleted or soft-deleted
        self.assertTrue(models.File.objects.filter(pk=file.id).exists())
        file_after = models.File.objects.get(pk=file.id)
        self.assertIsNone(file_after.delete_date)




