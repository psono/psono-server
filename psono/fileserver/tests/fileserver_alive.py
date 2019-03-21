from django.urls import reverse
from django.utils import timezone
from django.conf import settings

from rest_framework import status

from restapi.tests.base import APITestCaseExtended
from restapi.authentication import TokenAuthentication

from restapi.models import Fileserver_Cluster, Fileserver_Shard, Fileserver_Cluster_Shard_Link, Fileserver_Cluster_Members, Fileserver_Cluster_Member_Shard_Link
from restapi.utils import encrypt_with_db_secret

import nacl.encoding
import nacl.signing
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, PublicKey, Box

import os
import uuid
import json
import binascii
import datetime

class FileserverAlive(APITestCaseExtended):
    """
    Test to accept share rights
    """

    def setUp(self):
        box = PrivateKey.generate()
        self.cluster_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        self.cluster_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        private_key = encrypt_with_db_secret(self.cluster_private_key_hex)
        public_key = encrypt_with_db_secret(self.cluster_public_key_hex)

        self.cluster1 = Fileserver_Cluster.objects.create(
            title='Some Fileserver Cluster Title',
            auth_public_key=public_key,
            auth_private_key=private_key,
            file_size_limit=0,
        )

        self.shard1 = Fileserver_Shard.objects.create(
            title='Some Shard Title',
            description='Some Shard Description',
        )

        self.link1 = Fileserver_Cluster_Shard_Link.objects.create(
            cluster=self.cluster1,
            shard=self.shard1,
            read=True,
            write=True,
        )

        token_hash = TokenAuthentication.user_token_to_token_hash('abc')
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
            valid_till=timezone.now() + datetime.timedelta(seconds=30),
        )


    def test_alive_initial(self):
        """
        Tests to "ping" the server to announce a fileserver initially
        """

        # Generate fileserver info
        cluster_crypto_box = Box(PrivateKey(self.cluster_private_key_hex, encoder=nacl.encoding.HexEncoder),
                                 PublicKey(settings.PUBLIC_KEY, encoder=nacl.encoding.HexEncoder))

        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

        fileserver_id = str(uuid.uuid4())
        fileserver_session_key = nacl.encoding.HexEncoder.encode(
            nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)).decode()

        box = PrivateKey.generate()
        fileserver_private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder).decode()
        fileserver_public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder).decode()

        decrypted_fileserver_info = {
            'VERSION': '0.0.0 (abcd)',
            'HOSTNAME': 'example.com',
            'CLUSTER_ID': str(self.cluster1.id),
            'FILESERVER_ID': fileserver_id,
            'FILESERVER_PUBLIC_KEY': fileserver_public_key_hex,
            'FILESERVER_SESSION_KEY': fileserver_session_key,
            'SHARDS_PUBLIC': [{
                'shard_id': str(self.shard1.id),
                'read': True,
                'write': True,
                'delete': True
            }],
            'READ': True,
            'WRITE': True,
            'DELETE': True,
            'IP_READ_WHITELIST': [],
            'IP_WRITE_WHITELIST': [],
            'IP_READ_BLACKLIST': [],
            'IP_WRITE_BLACKLIST': [],
            'HOST_URL': 'https://fs01.example.com/fileserver',
        }

        encrypted = cluster_crypto_box.encrypt(json.dumps(decrypted_fileserver_info).encode("utf-8"), nonce)

        fileserver_info = nacl.encoding.HexEncoder.encode(encrypted).decode()

        url = reverse('fileserver_alive')

        data = {
        }

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + fileserver_id, HTTP_AUTHORIZATION_VALIDATOR=json.dumps({
            'fileserver_info': fileserver_info,
            'cluster_id': str(self.cluster1.id)
        }))
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        token_hash = TokenAuthentication.user_token_to_token_hash(fileserver_id)
        self.assertEqual(Fileserver_Cluster_Members.objects.filter(key=token_hash).count(), 1)

        fileserver = Fileserver_Cluster_Members.objects.get(key=token_hash)
        self.assertEqual(Fileserver_Cluster_Member_Shard_Link.objects.filter(member_id=fileserver.id, shard_id=str(self.shard1.id)).count(), 1)


    def test_alive_renewal(self):
        """
        Tests to "ping" the server to announce a fileserver as renewal
        """

        url = reverse('fileserver_alive')

        data = {
        }

        old_valid_till = self.fileserver1.valid_till

        self.client.force_authenticate(user=self.fileserver1)
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        updated_fs = Fileserver_Cluster_Members.objects.get(pk=self.fileserver1.pk)

        self.assertGreater(updated_fs.valid_till, old_valid_till)
