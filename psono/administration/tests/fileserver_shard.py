from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import _FileserverAdministrationTestCase


class FileserverShardViewTests(_FileserverAdministrationTestCase):
    def test_list_detail_search_ordering_and_pagination(self):
        self.authenticate()
        link = models.Fileserver_Cluster_Shard_Link.objects.create(
            cluster=self.cluster, shard=self.shard
        )
        url = reverse("admin_fileserver_shard")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            [item["id"] for item in response.data["shards"]], [self.shard.id]
        )
        response = self.client.get(
            url, {"search": "Main", "ordering": "title", "page_size": "1", "page": "0"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["shards"][0]["cluster_count"], 1)
        response = self.client.get(url, {"page_size": "1", "page": "100"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["shards"], [])
        response = self.client.get(
            reverse("admin_fileserver_shard", kwargs={"shard_id": self.shard.id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["links"][0]["id"], link.id)

    def test_list_rejects_non_numeric_page(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_shard"), {"page": "invalid"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page", response.data)

    def test_list_rejects_negative_page(self):
        self.authenticate()
        response = self.client.get(reverse("admin_fileserver_shard"), {"page": "-1"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page", response.data)

    def test_list_rejects_negative_page_size(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_shard"), {"page_size": "-1"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page_size", response.data)

    def test_list_rejects_non_numeric_page_size(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_shard"), {"page_size": "invalid"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page_size", response.data)

    def test_list_rejects_zero_page_size(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_shard"), {"page_size": "0"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("page_size", response.data)

    def test_list_rejects_unknown_ordering(self):
        self.authenticate()
        response = self.client.get(
            reverse("admin_fileserver_shard"), {"ordering": "invalid"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("ordering", response.data)

    def test_detail_rejects_missing_shard(self):
        from uuid import uuid4

        self.authenticate()
        self.assertEqual(
            self.client.get(
                reverse("admin_fileserver_shard", kwargs={"shard_id": uuid4()})
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_detail_rejects_malformed_identifier(self):
        self.authenticate()
        self.assertEqual(
            self.client.get(
                reverse("admin_fileserver_shard", kwargs={"shard_id": "invalid"})
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_creation_rejects_missing_fields(self):
        self.authenticate()
        url = reverse("admin_fileserver_shard")
        self.assertEqual(
            self.client.post(url, {}).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_update_rejects_missing_shard(self):
        from uuid import uuid4

        self.authenticate()
        response = self.client.put(
            reverse("admin_fileserver_shard"),
            {
                "shard_id": str(uuid4()),
                "title": "Missing",
                "description": "Missing",
                "active": True,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_rejects_missing_shard(self):
        from uuid import uuid4

        self.authenticate()
        response = self.client.delete(
            reverse("admin_fileserver_shard"), {"shard_id": str(uuid4())}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_shard_crud(self):
        self.authenticate()
        url = reverse("admin_fileserver_shard")
        response = self.client.post(
            url,
            {"title": "Archive shard", "description": "Archive", "active": False},
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        shard = models.Fileserver_Shard.objects.get(pk=response.data["id"])
        self.assertFalse(shard.active)

        response = self.client.put(
            url,
            {
                "shard_id": shard.id,
                "title": "Updated shard",
                "description": "Updated",
                "active": True,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        shard.refresh_from_db()
        self.assertEqual(shard.title, "Updated shard")
        self.assertTrue(shard.active)

        response = self.client.delete(url, {"shard_id": shard.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(models.Fileserver_Shard.objects.filter(pk=shard.id).exists())

    def test_shard_list_requires_admin_permissions(self):
        url = reverse("admin_fileserver_shard")
        self.assert_requires_admin_permissions("get", url)

    def test_shard_detail_requires_admin_permissions(self):
        url = reverse("admin_fileserver_shard", kwargs={"shard_id": self.shard.id})
        self.assert_requires_admin_permissions("get", url)

    def test_shard_create_requires_admin_permissions(self):
        url = reverse("admin_fileserver_shard")
        data = {"title": "New shard", "description": "Storage", "active": True}
        self.assert_requires_admin_permissions("post", url, data)

    def test_shard_update_requires_admin_permissions(self):
        url = reverse("admin_fileserver_shard")
        data = {
            "shard_id": self.shard.id,
            "title": "Updated shard",
            "description": "Updated storage",
            "active": True,
        }
        self.assert_requires_admin_permissions("put", url, data)

    def test_shard_delete_requires_admin_permissions(self):
        url = reverse("admin_fileserver_shard")
        data = {"shard_id": self.shard.id}
        self.assert_requires_admin_permissions("delete", url, data)
