from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import _FileserverAdministrationTestCase


class FileserverClusterShardLinkViewTests(_FileserverAdministrationTestCase):
    def test_cluster_shard_link_crud_and_member_revalidation(self):
        self.authenticate()
        url = reverse("admin_fileserver_cluster_shard_link")
        response = self.client.post(
            url,
            {
                "cluster_id": self.cluster.id,
                "shard_id": self.shard.id,
                "read": True,
                "write": False,
                "delete_capability": False,
                "allow_link_shares": False,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        link = models.Fileserver_Cluster_Shard_Link.objects.get(pk=response.data["id"])
        self.assertFalse(link.write)

        response = self.client.post(
            url, {"cluster_id": self.cluster.id, "shard_id": self.shard.id}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        member = self.create_member()
        response = self.client.put(
            url,
            {
                "link_id": link.id,
                "read": True,
                "write": True,
                "delete_capability": True,
                "allow_link_shares": True,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(
            models.Fileserver_Cluster_Members.objects.filter(pk=member.id).exists()
        )

        self.create_member()
        response = self.client.delete(url, {"link_id": link.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(
            models.Fileserver_Cluster_Shard_Link.objects.filter(pk=link.id).exists()
        )
        self.assertFalse(self.cluster.members.exists())

    def test_cluster_shard_link_create_requires_admin_permissions(self):
        url = reverse("admin_fileserver_cluster_shard_link")
        data = {"cluster_id": self.cluster.id, "shard_id": self.shard.id}
        self.assert_requires_admin_permissions("post", url, data)

    def test_cluster_shard_link_update_requires_admin_permissions(self):
        link = self.create_cluster_shard_link()
        url = reverse("admin_fileserver_cluster_shard_link")
        data = {
            "link_id": link.id,
            "read": True,
            "write": True,
            "delete_capability": True,
            "allow_link_shares": True,
        }
        self.assert_requires_admin_permissions("put", url, data)

    def test_cluster_shard_link_delete_requires_admin_permissions(self):
        link = self.create_cluster_shard_link()
        url = reverse("admin_fileserver_cluster_shard_link")
        data = {"link_id": link.id}
        self.assert_requires_admin_permissions("delete", url, data)
