from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import _FileserverAdministrationTestCase


class FileserverClusterViewTests(_FileserverAdministrationTestCase):
    def test_cluster_crud(self):
        self.authenticate()
        url = reverse("admin_fileserver_cluster")

        response = self.client.post(url, {"title": "Archive", "file_size_limit": 2048})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        cluster = models.Fileserver_Cluster.objects.get(pk=response.data["id"])
        self.assertTrue(cluster.auth_private_key)
        self.assertTrue(cluster.auth_public_key)

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["clusters"]), 2)
        self.assertNotIn("auth_private_key", response.data["clusters"][0])

        response = self.client.get(url, {"page": 99, "page_size": 1})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["clusters"], [])

        detail_url = reverse(
            "admin_fileserver_cluster", kwargs={"cluster_id": cluster.id}
        )
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn("auth_private_key", response.data)

        response = self.client.put(
            url,
            {
                "cluster_id": cluster.id,
                "title": "Updated archive",
                "file_size_limit": 4096,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        cluster.refresh_from_db()
        self.assertEqual(cluster.title, "Updated archive")
        self.assertEqual(cluster.file_size_limit, 4096)

        response = self.client.delete(url, {"cluster_id": cluster.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(
            models.Fileserver_Cluster.objects.filter(pk=cluster.id).exists()
        )

    def test_cluster_list_requires_admin_permissions(self):
        url = reverse("admin_fileserver_cluster")
        self.assert_requires_admin_permissions("get", url)

    def test_cluster_detail_requires_admin_permissions(self):
        url = reverse(
            "admin_fileserver_cluster", kwargs={"cluster_id": self.cluster.id}
        )
        self.assert_requires_admin_permissions("get", url)

    def test_cluster_create_requires_admin_permissions(self):
        url = reverse("admin_fileserver_cluster")
        data = {"title": "New cluster", "file_size_limit": 1024}
        self.assert_requires_admin_permissions("post", url, data)

    def test_cluster_update_requires_admin_permissions(self):
        url = reverse("admin_fileserver_cluster")
        data = {
            "cluster_id": self.cluster.id,
            "title": "Updated cluster",
            "file_size_limit": 2048,
        }
        self.assert_requires_admin_permissions("put", url, data)

    def test_cluster_delete_requires_admin_permissions(self):
        url = reverse("admin_fileserver_cluster")
        data = {"cluster_id": self.cluster.id}
        self.assert_requires_admin_permissions("delete", url, data)
