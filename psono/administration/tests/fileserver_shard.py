from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import _FileserverAdministrationTestCase


class FileserverShardViewTests(_FileserverAdministrationTestCase):
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
