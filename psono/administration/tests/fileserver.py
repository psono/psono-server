from datetime import timedelta

from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from restapi import models
from restapi.tests.base import APITestCaseExtended
from restapi.utils import encrypt_with_db_secret


class FileserverAdministrationTests(APITestCaseExtended):
    def setUp(self):
        user_data = {
            "authkey": "authkey",
            "public_key": "public-key",
            "private_key": "private-key",
            "secret_key": "secret-key",
            "user_sauce": "sauce",
            "is_email_active": True,
        }
        self.admin = models.User.objects.create(
            username="fileserver-admin@example.com",
            email=encrypt_with_db_secret("fileserver-admin@example.com"),
            email_bcrypt="admin-email-hash",
            private_key_nonce="private-key-nonce",
            secret_key_nonce="secret-key-nonce",
            is_staff=True,
            **user_data,
        )
        self.user = models.User.objects.create(
            username="fileserver-user@example.com",
            email=encrypt_with_db_secret("fileserver-user@example.com"),
            email_bcrypt="user-email-hash",
            private_key_nonce="private-key-nonce-2",
            secret_key_nonce="secret-key-nonce-2",
            **user_data,
        )
        self.cluster = models.Fileserver_Cluster.objects.create(
            title="Primary cluster",
            file_size_limit=1024,
            auth_public_key=encrypt_with_db_secret("public-key"),
            auth_private_key=encrypt_with_db_secret("private-key"),
        )
        self.shard = models.Fileserver_Shard.objects.create(
            title="Primary shard", description="Main storage"
        )

    def authenticate(self):
        self.client.force_authenticate(user=self.admin)

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

    def test_fileserver_list_and_detail_redact_secrets(self):
        member = self.create_member()
        models.Fileserver_Cluster_Members.objects.create(
            create_ip="127.0.0.1",
            key="expired-member-key",
            fileserver_cluster=self.cluster,
            public_key="expired-member-public-key",
            secret_key="expired-member-secret-key",
            url="https://expired-files.example.com",
            version="1.0.0",
            hostname="expired-files.example.com",
            valid_till=timezone.now() - timedelta(minutes=5),
        )
        models.Fileserver_Cluster_Member_Shard_Link.objects.create(
            member=member,
            shard=self.shard,
            ip_read_whitelist="[]",
            ip_read_blacklist="[]",
            ip_write_whitelist="[]",
            ip_write_blacklist="[]",
        )
        self.authenticate()

        response = self.client.get(reverse("admin_fileserver"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["fileservers"]), 1)
        self.assertNotIn("key", response.data["fileservers"][0])
        self.assertNotIn("secret_key", response.data["fileservers"][0])

        response = self.client.get(
            reverse("admin_fileserver", kwargs={"fileserver_id": member.id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["shards"][0]["shard_id"], self.shard.id)
        self.assertNotIn("key", response.data)
        self.assertNotIn("secret_key", response.data)

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

    def test_cluster_configuration_requires_admin_permissions(self):
        self.create_cluster_shard_link()
        url = reverse("admin_fileserver_cluster_configuration")
        data = {"cluster_id": self.cluster.id}
        self.assert_requires_admin_permissions("post", url, data)

    def test_fileserver_list_requires_admin_permissions(self):
        url = reverse("admin_fileserver")
        self.assert_requires_admin_permissions("get", url)

    def test_fileserver_detail_requires_admin_permissions(self):
        member = self.create_member()
        url = reverse("admin_fileserver", kwargs={"fileserver_id": member.id})
        self.assert_requires_admin_permissions("get", url)

    def assert_requires_admin_permissions(self, method, url, data=None):
        request = getattr(self.client, method)

        self.client.force_authenticate(user=None)
        response = request(url, data or {})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        self.client.force_authenticate(user=self.user)
        response = request(url, data or {})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def create_cluster_shard_link(self):
        return models.Fileserver_Cluster_Shard_Link.objects.create(
            cluster=self.cluster,
            shard=self.shard,
        )

    def create_member(self):
        return models.Fileserver_Cluster_Members.objects.create(
            create_ip="127.0.0.1",
            key=f"member-key-{self.cluster.members.count()}",
            fileserver_cluster=self.cluster,
            public_key="member-public-key",
            secret_key="member-secret-key",
            url="https://files.example.com",
            version="1.0.0",
            hostname="files.example.com",
            valid_till=timezone.now() + timedelta(minutes=5),
        )
