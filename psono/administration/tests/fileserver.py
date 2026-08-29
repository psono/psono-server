from datetime import timedelta

from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from restapi import models

from .helpers import _FileserverAdministrationTestCase


class FileserverViewTests(_FileserverAdministrationTestCase):
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

    def test_fileserver_list_requires_admin_permissions(self):
        url = reverse("admin_fileserver")
        self.assert_requires_admin_permissions("get", url)

    def test_fileserver_detail_requires_admin_permissions(self):
        member = self.create_member()
        url = reverse("admin_fileserver", kwargs={"fileserver_id": member.id})
        self.assert_requires_admin_permissions("get", url)
