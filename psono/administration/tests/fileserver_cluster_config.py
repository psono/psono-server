from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import _FileserverAdministrationTestCase


class FileserverClusterConfigViewTests(_FileserverAdministrationTestCase):
    def test_generate_cluster_configuration(self):
        models.Fileserver_Cluster_Shard_Link.objects.create(
            cluster=self.cluster, shard=self.shard
        )
        self.authenticate()
        response = self.client.post(
            reverse("admin_fileserver_cluster_configuration"),
            {"cluster_id": self.cluster.id},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("CLUSTER_PRIVATE_KEY", response.data["configuration"])
        self.assertIn(str(self.shard.id), response.data["configuration"])
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_cluster_configuration_requires_admin_permissions(self):
        self.create_cluster_shard_link()
        url = reverse("admin_fileserver_cluster_configuration")
        data = {"cluster_id": self.cluster.id}
        self.assert_requires_admin_permissions("post", url, data)
