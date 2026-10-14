from django.utils import timezone
from datetime import timedelta

from django.urls import reverse

from rest_framework import status

from restapi import models

from .base import APITestCaseExtended


class ShardTests(APITestCaseExtended):
    def test_put_is_not_supported(self):
        self.client.force_authenticate(user=self.test_user_obj)
        self.assertEqual(
            self.client.put(reverse("shard"), {}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def test_post_is_not_supported(self):
        self.client.force_authenticate(user=self.test_user_obj)
        self.assertEqual(
            self.client.post(reverse("shard"), {}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def test_delete_is_not_supported(self):
        self.client.force_authenticate(user=self.test_user_obj)
        self.assertEqual(
            self.client.delete(reverse("shard"), {}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "asd"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "abc"
        self.test_username = "test@psono.pw"
        self.test_username2 = "test2@psono.pw"
        self.test_password = "myPassword"
        self.test_authkey = (
            "c55066421a559f76d8ed5227622e9f95a0c67df15220e40d7bc98a8a598124fa15373ac553ef3ee27c7"
            "123d6be058e6d43cc71c1b666bdecaf33b734c8583a93"
        )
        self.test_public_key = (
            "5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        )
        self.test_secret_key = (
            "a7d028388e9d80f2679c236ebb2d0fedc5b7b0a28b393f6a20cc8f6be636aa71"
        )
        self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce2 = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_secret_key_enc = (
            "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422"
            "7a4faf06969a7404961f855841e5d5d1baba935f35fa522553ef3ee27c7123d6be058e6d43cc7"
            "1c1b666bdecaf33b734c8583a93"
        )
        self.test_private_key = (
            "a114c8fe9d69c7a2764d3d9e5d16f374a8eb0910f41d8c9c5ed8993bbff43295"
        )
        self.test_private_key_enc = (
            "16d9486b1e6ad9a29023a461a0d36ceef48a553697cbba2acc3530a6bb06f2e2798c5e10b369f9f"
            "4af8999d5a1b0e08f5ee7878139caf2b8c55e6cd0c936f2891"
        )
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"
        self.test_private_key_nonce2 = (
            "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb8"
        )
        self.test_user_obj = models.User.objects.create(
            email=self.test_email,
            email_bcrypt=self.test_email_bcrypt,
            username=self.test_username,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce,
            user_sauce="3e7a12fcb7171c917005ef8110503ffbb85764163dbb567ef481e72a37f352a7",
            is_email_active=True,
        )

        self.test_user2_obj = models.User.objects.create(
            email=self.test_email2,
            email_bcrypt=self.test_email_bcrypt2,
            username=self.test_username2,
            authkey="abc",
            public_key=self.test_public_key,
            private_key=self.test_private_key_enc,
            private_key_nonce=self.test_private_key_nonce2,
            secret_key=self.test_secret_key_enc,
            secret_key_nonce=self.test_secret_key_nonce2,
            user_sauce="f3c0a6788364ab164d574b655ac2a90b8124d3a20fd341c38a24566188390d01",
            is_email_active=True,
        )

    def _create_api_key_session_token(
        self, restrict_to_secrets=False, read=True, write=True
    ):
        api_key = models.API_Key.objects.create(
            user=self.test_user_obj,
            title="Test API Key",
            public_key="B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5",
            private_key="a123",
            private_key_nonce="B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5",
            secret_key="a123",
            secret_key_nonce="B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5",
            user_private_key="a123",
            user_private_key_nonce="B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5",
            user_secret_key="a123",
            user_secret_key_nonce="B52032040066AE04BECBBB03286469223731B0E8A2298F26DC5F01222E63D0F5",
            verify_key="a123",
            read=True,
            write=True,
            restrict_to_secrets=restrict_to_secrets,
            allow_insecure_access=True,
        )
        token = models.Token.objects.create(
            user=self.test_user_obj,
            api_key=api_key,
            active=True,
            read=read,
            write=write,
            valid_till=timezone.now() + timedelta(hours=1),
        )
        return token

    def test_live_fileservers_are_grouped_and_permissions_are_aggregated(self):
        shard = models.Fileserver_Shard.objects.create(
            title="Shard", description="Storage", active=True
        )
        cluster = models.Fileserver_Cluster.objects.create(
            title="Cluster",
            auth_public_key="key",
            auth_private_key="key",
            file_size_limit=0,
        )
        reader = models.Fileserver_Cluster_Members.objects.create(
            create_ip="127.0.0.1",
            fileserver_cluster=cluster,
            key="reader",
            public_key="key",
            secret_key="secret",
            url="https://reader.example.com",
            read=True,
            write=False,
            valid_till=timezone.now() + timedelta(minutes=5),
        )
        writer = models.Fileserver_Cluster_Members.objects.create(
            create_ip="127.0.0.1",
            fileserver_cluster=cluster,
            key="writer",
            public_key="key",
            secret_key="secret",
            url="https://writer.example.com",
            read=False,
            write=True,
            valid_till=timezone.now() + timedelta(minutes=5),
        )
        inactive = models.Fileserver_Cluster_Members.objects.create(
            create_ip="127.0.0.1",
            fileserver_cluster=cluster,
            key="inactive",
            public_key="key",
            secret_key="secret",
            url="https://inactive.example.com",
            read=False,
            write=False,
            valid_till=timezone.now() + timedelta(minutes=5),
        )
        models.Fileserver_Cluster_Member_Shard_Link.objects.create(
            member=reader,
            shard=shard,
            read=True,
            write=True,
            ip_read_whitelist="[]",
            ip_read_blacklist="[]",
            ip_write_whitelist="[]",
            ip_write_blacklist="[]",
        )
        models.Fileserver_Cluster_Member_Shard_Link.objects.create(
            member=writer,
            shard=shard,
            read=True,
            write=True,
            ip_read_whitelist="[]",
            ip_read_blacklist="[]",
            ip_write_whitelist="[]",
            ip_write_blacklist="[]",
        )
        models.Fileserver_Cluster_Member_Shard_Link.objects.create(
            member=inactive,
            shard=shard,
            read=True,
            write=True,
            ip_read_whitelist="[]",
            ip_read_blacklist="[]",
            ip_write_whitelist="[]",
            ip_write_blacklist="[]",
        )
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(reverse("shard"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["shards"]), 1)
        result = response.data["shards"][0]
        self.assertEqual(result["id"], shard.id)
        self.assertTrue(result["read"])
        self.assertTrue(result["write"])
        self.assertEqual(len(result["fileserver"]), 3)
        self.assertEqual(
            sorted((node["read"], node["write"]) for node in result["fileserver"]),
            [(False, False), (False, True), (True, False)],
        )

    def test_read_rejects_non_object_json_request_body(self):
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.generic(
            "GET", reverse("shard"), data='["invalid"]', content_type="application/json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_success(self):
        """
        Tests GET on shard with a regular token
        """

        token = models.Token.objects.create(
            user=self.test_user_obj,
            active=True,
            valid_till=timezone.now() + timedelta(hours=1),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.clear_text_key}")
        response = self.client.get(reverse("shard"), {})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("shards", response.data)

    def test_read_with_restricted_api_key_session(self):
        """
        Tests that a session of an API key restricted to secrets cannot read shards
        """

        token = self._create_api_key_session_token(restrict_to_secrets=True)

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.clear_text_key}")
        response = self.client.get(reverse("shard"), {})

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"detail": "API_KEY_RESTRICTED_TO_SECRETS"})

    def test_read_with_api_key_session_without_read_permission(self):
        """
        Tests that an API key session token without read permission cannot read shards
        """

        token = self._create_api_key_session_token(read=False)

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.clear_text_key}")
        response = self.client.get(reverse("shard"), {})

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_read_unauthenticated(self):
        """
        Tests GET on shard unauthenticated
        """

        response = self.client.get(reverse("shard"), {})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
