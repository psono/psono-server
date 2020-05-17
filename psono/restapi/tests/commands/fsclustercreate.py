from django.core.management import call_command
from django.test import TestCase

from restapi import models

from io import StringIO


class CommandFSClusterCreateTestCase(TestCase):

    def test_create_cluster(self):
        """
        Tests to create a cluster
        """

        cluster_title = 'Some Cluster Title'

        args = [cluster_title]
        opts = {}

        out = StringIO()
        call_command('fsclustercreate', stdout=out, *args, **opts)

        self.assertTrue(models.Fileserver_Cluster.objects.filter(title=cluster_title).exists())



