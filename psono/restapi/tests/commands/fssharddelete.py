from django.core.management import call_command
from django.test import TestCase

from restapi import models

from io import StringIO


class CommandFSShardDeleteTestCase(TestCase):

    def setUp(self):

        self.shard = models.Fileserver_Shard.objects.create(
            title='Some Title',
            description='Some description',
        )

    def test_delete_shard(self):
        """
        Tests to delete a shard
        """

        args = [str(self.shard.id)]
        opts = {}

        out = StringIO()
        call_command('fssharddelete', stdout=out, *args, **opts)

        self.assertEqual(models.Fileserver_Shard.objects.count(), 0)



