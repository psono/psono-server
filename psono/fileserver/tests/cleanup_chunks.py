from django.urls import reverse
from django.utils import timezone
from django.conf import settings

from rest_framework import status

from restapi.tests.base import APITestCaseExtended
from restapi.authentication import TokenAuthentication

from restapi.models import (
    Fileserver_Cluster, Fileserver_Shard, Fileserver_Cluster_Shard_Link,
    Fileserver_Cluster_Members, Fileserver_Cluster_Member_Shard_Link,
    User, File, File_Chunk, File_Link
)
from restapi.utils import encrypt_with_db_secret

import nacl.encoding
import nacl.utils
from nacl.public import PrivateKey

import os
import binascii
import datetime
import uuid


class CleanupChunksTest(APITestCaseExtended):
    """
    Test to cleanup chunks
    """

    def setUp(self):
        # Create cluster
        box = PrivateKey.generate()
        self.cluster_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.cluster_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        private_key = encrypt_with_db_secret(self.cluster_private_key_hex)
        public_key = encrypt_with_db_secret(self.cluster_public_key_hex)

        self.cluster1 = Fileserver_Cluster.objects.create(
            title='Test Cluster',
            auth_public_key=public_key,
            auth_private_key=private_key,
            file_size_limit=0,
        )

        # Create shard
        self.shard1 = Fileserver_Shard.objects.create(
            title='Test Shard',
            description='Test Shard Description',
            active=True,
        )

        self.shard2 = Fileserver_Shard.objects.create(
            title='Test Shard 2',
            description='Test Shard 2 Description',
            active=True,
        )

        # Link cluster and shard
        self.cluster_shard_link = Fileserver_Cluster_Shard_Link.objects.create(
            cluster=self.cluster1,
            shard=self.shard1,
            read=True,
            write=True,
            delete_capability=True,
        )

        # Create fileserver member
        token_hash = TokenAuthentication.user_token_to_token_hash('test-token')
        self.fileserver1 = Fileserver_Cluster_Members.objects.create(
            create_ip='127.0.0.1',
            fileserver_cluster=self.cluster1,
            key=token_hash,
            public_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            secret_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            url='https://fs01.example.com/fileserver',
            read=True,
            write=True,
            delete_capability=True,
            valid_till=timezone.now() + datetime.timedelta(seconds=300),
        )

        # Link fileserver member to shard
        self.member_shard_link = Fileserver_Cluster_Member_Shard_Link.objects.create(
            member=self.fileserver1,
            shard=self.shard1,
            read=True,
            write=True,
            delete_capability=True,
        )

        # Create a user for file ownership
        self.user = User.objects.create(
            email='test@example.com',
            email_bcrypt='',
            username='testuser',
            authkey='abc',
            public_key='public_key',
            private_key='private_key',
            private_key_nonce='private_key_nonce',
            secret_key='secret_key',
            secret_key_nonce='secret_key_nonce',
            user_sauce='90272aaf01a2d525f74a',
            is_email_active=True
        )

        # Create file with delete_date in the past
        self.file1 = File.objects.create(
            shard=self.shard1,
            file_repository_id=None,
            chunk_count=2,
            size=1024,
            delete_date=timezone.now() - datetime.timedelta(days=1),
        )

        # Create file chunks
        self.chunk1 = File_Chunk.objects.create(
            hash_checksum='chunk1hash',
            position=0,
            user=self.user,
            file=self.file1,
            size=512,
        )

        self.chunk2 = File_Chunk.objects.create(
            hash_checksum='chunk2hash',
            position=1,
            user=self.user,
            file=self.file1,
            size=512,
        )

    def test_get_cleanup_chunks_success(self):
        """
        Tests GET request to retrieve chunks that should be cleaned up
        """
        url = reverse('fileserver_cleanup_chunks')

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('shards', response.data)
        self.assertIsInstance(response.data['shards'], dict)

        # Check that our shard is in the response
        shard_id_str = str(self.shard1.id)
        if shard_id_str in response.data['shards']:
            self.assertIn('chunk1hash', response.data['shards'][shard_id_str])
            self.assertIn('chunk2hash', response.data['shards'][shard_id_str])

    def test_get_cleanup_chunks_no_delete_capability(self):
        """
        Tests GET request when fileserver has no delete capability
        """
        # Remove delete capability
        self.member_shard_link.delete_capability = False
        self.member_shard_link.save()

        url = reverse('fileserver_cleanup_chunks')

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['shards'], {})

    def test_get_cleanup_chunks_expired_fileserver(self):
        """
        Tests GET request with expired fileserver
        """
        # Expire the fileserver
        self.fileserver1.valid_till = timezone.now() - datetime.timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT + 10)
        self.fileserver1.save()

        url = reverse('fileserver_cleanup_chunks')

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['shards'], {})

    def test_get_cleanup_chunks_multiple_fileservers(self):
        """
        Tests GET request with multiple fileservers for position calculation
        """
        # Create second fileserver
        token_hash2 = TokenAuthentication.user_token_to_token_hash('test-token-2')
        fileserver2 = Fileserver_Cluster_Members.objects.create(
            create_ip='127.0.0.2',
            fileserver_cluster=self.cluster1,
            key=token_hash2,
            public_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            secret_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            url='https://fs02.example.com/fileserver',
            read=True,
            write=True,
            delete_capability=True,
            valid_till=timezone.now() + datetime.timedelta(seconds=300),
        )

        Fileserver_Cluster_Member_Shard_Link.objects.create(
            member=fileserver2,
            shard=self.shard1,
            read=True,
            write=True,
            delete_capability=True,
        )

        url = reverse('fileserver_cleanup_chunks')

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('shards', response.data)

    def test_post_cleanup_chunks_success(self):
        """
        Tests POST request to confirm chunk deletion
        """
        url = reverse('fileserver_cleanup_chunks')

        data = {
            'deleted_chunks': [
                {
                    'shard_id': str(self.shard1.id),
                    'chunks': ['chunk1hash', 'chunk2hash']
                }
            ]
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify chunks were deleted
        self.assertEqual(File_Chunk.objects.filter(hash_checksum='chunk1hash').count(), 0)
        self.assertEqual(File_Chunk.objects.filter(hash_checksum='chunk2hash').count(), 0)

        # Verify file was deleted (since it has no chunks left and delete_date is in the past)
        self.assertEqual(File.objects.filter(id=self.file1.id).count(), 0)

    def test_post_cleanup_chunks_no_permission(self):
        """
        Tests POST request when fileserver has no delete permission
        """
        # Remove delete capability
        self.member_shard_link.delete_capability = False
        self.member_shard_link.save()

        url = reverse('fileserver_cleanup_chunks')

        data = {
            'deleted_chunks': [
                {
                    'shard_id': str(self.shard1.id),
                    'chunks': ['chunk1hash']
                }
            ]
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_cleanup_chunks_wrong_shard(self):
        """
        Tests POST request with chunk from different shard
        """
        # Create file on different shard
        file2 = File.objects.create(
            shard=self.shard2,
            file_repository_id=None,
            chunk_count=1,
            size=512,
            delete_date=timezone.now() - datetime.timedelta(days=1),
        )

        chunk3 = File_Chunk.objects.create(
            hash_checksum='chunk3hash',
            position=0,
            user=self.user,
            file=file2,
            size=512,
        )

        url = reverse('fileserver_cleanup_chunks')

        # Try to delete chunk from shard2 while claiming it's from shard1
        data = {
            'deleted_chunks': [
                {
                    'shard_id': str(self.shard1.id),
                    'chunks': ['chunk3hash']  # This chunk belongs to shard2
                }
            ]
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_cleanup_chunks_expired_fileserver(self):
        """
        Tests POST request with expired fileserver
        """
        # Expire the fileserver
        self.fileserver1.valid_till = timezone.now() - datetime.timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT + 10)
        self.fileserver1.save()

        url = reverse('fileserver_cleanup_chunks')

        data = {
            'deleted_chunks': [
                {
                    'shard_id': str(self.shard1.id),
                    'chunks': ['chunk1hash']
                }
            ]
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_cleanup_chunks_no_write_permission(self):
        """
        Tests POST request when fileserver member has no write permission
        """
        self.fileserver1.write = False
        self.fileserver1.save()

        url = reverse('fileserver_cleanup_chunks')

        data = {
            'deleted_chunks': [
                {
                    'shard_id': str(self.shard1.id),
                    'chunks': ['chunk1hash']
                }
            ]
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_cleanup_chunks_inactive_shard(self):
        """
        Tests POST request with inactive shard
        """
        self.shard1.active = False
        self.shard1.save()

        url = reverse('fileserver_cleanup_chunks')

        data = {
            'deleted_chunks': [
                {
                    'shard_id': str(self.shard1.id),
                    'chunks': ['chunk1hash']
                }
            ]
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_cleanup_chunks_empty_list(self):
        """
        Tests POST request with empty deleted_chunks list
        """
        url = reverse('fileserver_cleanup_chunks')

        data = {
            'deleted_chunks': []
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_not_allowed(self):
        """
        Tests that PUT method is not allowed
        """
        url = reverse('fileserver_cleanup_chunks')

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, {})

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_not_allowed(self):
        """
        Tests that DELETE method is not allowed
        """
        url = reverse('fileserver_cleanup_chunks')

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_get_cleanup_chunks_with_expired_link_in_past(self):
        """
        Tests position=None case triggering continue statement
        """
        token_hash2 = TokenAuthentication.user_token_to_token_hash('test-token-valid')
        fileserver2 = Fileserver_Cluster_Members.objects.create(
            create_ip='127.0.0.2',
            fileserver_cluster=self.cluster1,
            key=token_hash2,
            public_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            secret_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            url='https://fs02.example.com/fileserver',
            read=True,
            write=True,
            delete_capability=True,
            valid_till=timezone.now() + datetime.timedelta(seconds=300),
        )

        Fileserver_Cluster_Member_Shard_Link.objects.create(
            member=fileserver2,
            shard=self.shard1,
            read=True,
            write=True,
            delete_capability=True,
        )

        self.fileserver1.valid_till = timezone.now() - datetime.timedelta(seconds=settings.FILESERVER_ALIVE_TIMEOUT + 10)
        self.fileserver1.save()

        url = reverse('fileserver_cleanup_chunks')

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['shards'], {})

    def test_get_serializer_class_non_post(self):
        """
        Tests get_serializer_class returns Serializer for non-POST
        """
        from fileserver.views.cleanup_chunks import CleanupChunksView
        from rest_framework.test import APIRequestFactory

        factory = APIRequestFactory()
        request = factory.get(reverse('fileserver_cleanup_chunks'))
        request.user = self.fileserver1

        view = CleanupChunksView()
        view.request = request

        serializer_class = view.get_serializer_class()
        from rest_framework.serializers import Serializer
        self.assertEqual(serializer_class, Serializer)

    def test_post_cleanup_chunks_multiple_shards(self):
        """
        Tests POST request with multiple shards
        """
        # Create another shard and link it
        Fileserver_Cluster_Shard_Link.objects.create(
            cluster=self.cluster1,
            shard=self.shard2,
            read=True,
            write=True,
            delete_capability=True,
        )

        Fileserver_Cluster_Member_Shard_Link.objects.create(
            member=self.fileserver1,
            shard=self.shard2,
            read=True,
            write=True,
            delete_capability=True,
        )

        # Create file on shard2
        file2 = File.objects.create(
            shard=self.shard2,
            file_repository_id=None,
            chunk_count=1,
            size=512,
            delete_date=timezone.now() - datetime.timedelta(days=1),
        )

        chunk3 = File_Chunk.objects.create(
            hash_checksum='chunk3hash',
            position=0,
            user=self.user,
            file=file2,
            size=512,
        )

        url = reverse('fileserver_cleanup_chunks')

        data = {
            'deleted_chunks': [
                {
                    'shard_id': str(self.shard1.id),
                    'chunks': ['chunk1hash']
                },
                {
                    'shard_id': str(self.shard2.id),
                    'chunks': ['chunk3hash']
                }
            ]
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify chunks were deleted
        self.assertEqual(File_Chunk.objects.filter(hash_checksum='chunk1hash').count(), 0)
        self.assertEqual(File_Chunk.objects.filter(hash_checksum='chunk3hash').count(), 0)
