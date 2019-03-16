from django.core.management import call_command
from django.test import TestCase
import nacl.encoding
from nacl.public import PrivateKey
from restapi.utils import encrypt_with_db_secret

from restapi import models

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class CommandFSClusterListTestCase(TestCase):

    def setUp(self):
        box = PrivateKey.generate()
        private_key_hex = box.encode(encoder=nacl.encoding.HexEncoder)
        public_key_hex = box.public_key.encode(encoder=nacl.encoding.HexEncoder)

        private_key_hex = encrypt_with_db_secret(private_key_hex.decode())
        public_key_hex = encrypt_with_db_secret(public_key_hex.decode())

        self.cluster = models.Fileserver_Cluster.objects.create(
            title='Some Title',
            auth_public_key=public_key_hex,
            auth_private_key=private_key_hex,
            file_size_limit=0,
        )

        self.shard = models.Fileserver_Shard.objects.create(
            title='Some Title',
            description='Some description',
        )

        self.link = models.Fileserver_Cluster_Shard_Link.objects.create(
            cluster=self.cluster,
            shard=self.shard,
            read=True,
            write=True,
        )

    def test_list_all_clusters(self):
        """
        Tests to list all clusters
        """

        args = []
        opts = {}

        out = StringIO()
        call_command('fsclusterlist', stdout=out, *args, **opts)



