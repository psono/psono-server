from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import _FileserverAdministrationTestCase


class FileserverClusterViewTests(_FileserverAdministrationTestCase):
    def test_cluster_rejects_non_numeric_page(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_cluster"), {"page": "invalid"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page", response.data)

    def test_cluster_rejects_negative_page(self):
        self.authenticate()
        response = self.client.get(reverse("admin_fileserver_cluster"), {"page": "-1"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page", response.data)

    def test_cluster_rejects_negative_page_size(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_cluster"), {"page_size": "-1"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page_size", response.data)

    def test_cluster_rejects_non_numeric_page_size(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_cluster"), {"page_size": "invalid"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page_size", response.data)

    def test_cluster_rejects_zero_page_size(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_cluster"), {"page_size": "0"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page_size", response.data)

    def test_cluster_rejects_invalid_ordering(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_cluster"), {"ordering": "invalid"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("ordering", response.data)

    def test_cluster_search_returns_matching_cluster(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_cluster"),
            {
                "search": self.cluster.title,
                "page_size": "1",
                "page": "0",
                "ordering": "title",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["clusters"][0]["id"], self.cluster.id)

    def test_cluster_populated_detail(self):
        member = self.create_member()
        link = self.create_cluster_shard_link()
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_cluster", kwargs={"cluster_id": self.cluster.id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["links"][0]["id"], link.id)
        self.assertEqual(response.data["fileservers"][0]["id"], member.id)

    def test_cluster_detail_rejects_missing_cluster(self):
        from uuid import uuid4

        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_cluster", kwargs={"cluster_id": str(uuid4())})
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cluster_detail_rejects_malformed_id(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_cluster", kwargs={"cluster_id": "invalid"})
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cluster_creation_requires_fields(self):
        self.authenticate()
        response = self.client.post(reverse("admin_fileserver_cluster"), {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cluster_update_rejects_missing_cluster(self):
        from uuid import uuid4

        self.authenticate()
        response = self.client.put(
            reverse("admin_fileserver_cluster"),
            {"cluster_id": str(uuid4()), "title": "Missing", "file_size_limit": 1},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cluster_delete_rejects_missing_cluster(self):
        from uuid import uuid4

        self.authenticate()
        response = self.client.delete(
            reverse("admin_fileserver_cluster"), {"cluster_id": str(uuid4())}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

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
