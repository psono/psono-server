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


class CommandFSClusterDeleteTestCase(TestCase):

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

    def test_delete_cluster(self):
        """
        Tests to delete a cluster
        """

        args = [str(self.cluster.id)]
        opts = {}

        out = StringIO()
        call_command('fsclusterdelete', stdout=out, *args, **opts)

        self.assertEqual(models.Fileserver_Cluster.objects.count(), 0)



