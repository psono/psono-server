from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from datetime import timedelta
from rest_framework import status

from restapi import models
from restapi.authentication import TokenAuthentication
from restapi.renderers import encrypt
from restapi.utils import encrypt_with_db_secret

from restapi.tests.base import APITestCaseExtended

import binascii
import random
import string
import os
import json
import datetime

import nacl.encoding
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey


class AuthorizeUploadTests(APITestCaseExtended):

    def setUp(self):

        self.test_email = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@example.com'
        self.test_email_bcrypt = 'a'
        self.test_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + 'test@psono.pw'
        self.test_authkey = binascii.hexlify(os.urandom(settings.AUTH_KEY_LENGTH_BYTES)).decode()
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
            authkey=make_password(self.test_authkey),
            public_key=self.test_public_key,
            private_key=self.test_private_key,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce=self.test_user_sauce,
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
            email=encrypt_with_db_secret(self.test_email2),
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

        self.user_token = ''.join(random.choice(string.ascii_lowercase) for _ in range(64))
        self.user_db_token = models.Token.objects.create(
            key=TokenAuthentication.user_token_to_token_hash(self.user_token),
            user=self.test_user_obj,
            secret_key = binascii.hexlify(os.urandom(32)).decode(),
            valid_till=timezone.now() + timedelta(seconds=10),
            active=True,
        )
        # Create Fileserver
        box = PrivateKey.generate()
        self.cluster_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.cluster_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        private_key = encrypt_with_db_secret(self.cluster_private_key_hex)
        public_key = encrypt_with_db_secret(self.cluster_public_key_hex)

        self.cluster1 = models.Fileserver_Cluster.objects.create(
            title='Some Fileserver Cluster Title',
            auth_public_key=public_key,
            auth_private_key=private_key,
            file_size_limit=0,
        )

        self.shard1 = models.Fileserver_Shard.objects.create(
            title='Some Shard Title',
            description='Some Shard Description',
        )

        self.link1 = models.Fileserver_Cluster_Shard_Link.objects.create(
            cluster=self.cluster1,
            shard=self.shard1,
            read=True,
            write=True,
        )

        token_hash = TokenAuthentication.user_token_to_token_hash('abc')
        self.fileserver1 = models.Fileserver_Cluster_Members.objects.create(
            create_ip='127.0.0.1',
            fileserver_cluster=self.cluster1,
            key=token_hash,
            public_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            secret_key=binascii.hexlify(os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)).decode(),
            url='https://fs01.example.com/fileserver',
            read=True,
            write=True,
            delete_capability=True,
            valid_till=timezone.now() + datetime.timedelta(seconds=30),
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

        self.file_size = 140

        self.file = models.File.objects.create(
            shard=self.shard1,
            file_repository_id=None,
            chunk_count=1,
            size=self.file_size,
            user=self.test_user_obj,
        )

        self.file_transfer = models.File_Transfer.objects.create(
            user=self.test_user_obj,
            shard=self.shard1,
            file_repository_id=self.file.file_repository_id,
            file=self.file,
            size=self.file_size,
            size_transferred=0,
            chunk_count=1,
            chunk_count_transferred=0,
            credit=0,
            type='upload',
            )


    def test_successful(self):
        """
        Tests authorize upload successful
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        chunk_size = self.file_size

        data = {
            'token': self.user_token,
            'chunk_size': chunk_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue('shard_id' in response.data)
        self.assertEqual(str(response.data['shard_id']), str(self.shard1.id))

        self.assertEqual(models.File_Chunk.objects.count(), 1)

        refreshed_file_transfer = models.File_Transfer.objects.get(pk=self.file_transfer.id)

        self.assertEqual(self.file_transfer.size_transferred + chunk_size, refreshed_file_transfer.size_transferred)
        self.assertEqual(self.file_transfer.chunk_count_transferred + 1, refreshed_file_transfer.chunk_count_transferred)

    def test_failure_missing_token(self):
        """
        Tests authorize upload failure with a missing token
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            # 'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_token_not_active(self):
        """
        Tests authorize upload failure with a token that is not active
        """

        self.user_db_token.active = False
        self.user_db_token.save()

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_ticket_decryption_fail(self):
        """
        Tests authorize upload failure with a token where the decryption fails
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        self.user_db_token.secret_key = binascii.hexlify(os.urandom(32)).decode()
        self.user_db_token.save()

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_missing_file_transfer_id(self):
        """
        Tests authorize upload failure with a ticket that does not have a file_transfer_id
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            # 'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_missing_chunk_position(self):
        """
        Tests authorize upload failure with a ticket that does not have a chunk position
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            # 'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_missing_hash_checksum(self):
        """
        Tests authorize upload failure with a ticket that does not have a hash_checksum
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            # 'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_chunk_size_limit_too_small(self):
        """
        Tests authorize upload failure with a chunk_size_limit that is smaller than 40
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': 39,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_chunk_size_limit_too_big(self):
        """
        Tests authorize upload failure with a chunk_size_limit that is bigger than 128 * 1024 * 1024 + 40
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': 128 * 1024 * 1024 + 40 + 1,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_failure_mismatching_hash_checksums(self):
        """
        Tests authorize upload failure with a hash checksum from the ticket that does not match the hash checksum that
        the fileserver calculated
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': 'ABCD',
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_not_existing_file_transfer(self):
        """
        Tests authorize upload failure with a file transfer that does not exist
        """

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': '76f4cc5a-b20d-494c-b922-81e7eaacea66',
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_file_transfer_belongs_to_other_user(self):
        """
        Tests authorize upload failure with a file transfer that does not belong to the authenticated user
        """

        self.file_transfer.user = self.test_user_obj2
        self.file_transfer.save()

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_file_transfer_is_no_upload(self):
        """
        Tests authorize upload failure with a file transfer that is no upload
        """

        self.file_transfer.type = 'download'
        self.file_transfer.save()

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_nonauthorized_fileserver(self):
        """
        Tests authorize upload failure with a fileserver that is not authorized
        """

        models.Fileserver_Cluster_Member_Shard_Link.objects.all().delete()

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_chunk_count_transfered_exceeded(self):
        """
        Tests authorize upload failure with a file transfer where the chunk count has already used completely
        """

        self.file_transfer.chunk_count_transferred = self.file_transfer.chunk_count
        self.file_transfer.save()

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_failure_size_transfered_exceeded(self):
        """
        Tests authorize upload failure with a file transfer where the transfered bytes have already been used completely
        """

        self.file_transfer.size_transferred = self.file_transfer.size
        self.file_transfer.save()

        url = reverse('fileserver_authorize_upload')

        hash_checksum = 'ABC'

        ticket_decrypted = {
            'file_transfer_id': str(self.file_transfer.id),
            'chunk_position': 1,
            'hash_checksum': hash_checksum,
        }

        ticket_encrypted = encrypt(self.user_db_token.secret_key, json.dumps(ticket_decrypted).encode())

        data = {
            'token': self.user_token,
            'chunk_size': self.file_size,
            'hash_checksum': hash_checksum,
            'ip_address': '127.0.0.1',
            'ticket': ticket_encrypted['text'].decode(),
            'ticket_nonce': ticket_encrypted['nonce'].decode(),
        }

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
