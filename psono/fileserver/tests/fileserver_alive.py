from django.urls import reverse
from django.utils import timezone
from django.conf import settings

from rest_framework import status

from restapi.tests.base import APITestCaseExtended
from restapi.authentication import TokenAuthentication

from nacl.public import PrivateKey
from restapi.models import Fileserver_Cluster, Fileserver_Shard, Fileserver_Cluster_Shard_Link, Fileserver_Cluster_Members
from restapi.utils import encrypt_with_db_secret
import nacl.encoding

import os
import binascii
import datetime

class FileserverAlive(APITestCaseExtended):
    """
    Test to accept share rights
    """

    def setUp(self):
        box = PrivateKey.generate()
        private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)

        private_key_hex = encrypt_with_db_secret(private_key_hex.decode())
        public_key_hex = encrypt_with_db_secret(public_key_hex.decode())

        self.cluster1 = Fileserver_Cluster.objects.create(
            title='Some Fileserver Cluster Title',
            auth_public_key=public_key_hex,
            auth_private_key=private_key_hex,
            file_size_limit=0,
        )

        self.cluster1 = Fileserver_Cluster.objects.create(
            title='Some Fileserver Cluster Title',
            auth_public_key=public_key_hex,
            auth_private_key=private_key_hex,
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
            delete=True,
            valid_till=timezone.now() + datetime.timedelta(seconds=30),
        )


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
