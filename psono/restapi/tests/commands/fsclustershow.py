from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from restapi.management.commands.fsclustercreate import create_cluster


class CommandFSClusterShowTestCase(TestCase):
    def test_show_clusters(self):
        first_cluster = create_cluster("First cluster", file_size_limit=0)["cluster"]
        second_cluster = create_cluster("Second cluster", file_size_limit=0)["cluster"]
        output = StringIO()

        call_command("fsclustershow", stdout=output)

        self.assertEqual(
            output.getvalue().splitlines(),
            [
                f"Cluster: First cluster (ID: {first_cluster.id})",
                f"Cluster: Second cluster (ID: {second_cluster.id})",
            ],
        )
