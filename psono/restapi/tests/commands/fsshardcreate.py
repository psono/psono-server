from django.core.management import call_command
from django.test import TestCase

from restapi import models

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class CommandFSShardCreateTestCase(TestCase):

    def test_create_shard(self):
        """
        Tests to create a shard
        """

        shard_title = 'Some Cluster Title'
        shard_description = 'Some Cluster Description'

        args = [shard_title, shard_description]
        opts = {}

        out = StringIO()
        call_command('fsshardcreate', stdout=out, *args, **opts)

        self.assertTrue(models.Fileserver_Shard.objects.filter(title=shard_title, description=shard_description).exists())



