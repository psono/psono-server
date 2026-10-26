import json
import os
import binascii
import random
import string
from uuid import uuid4
from urllib.parse import parse_qs, urlsplit
from django.conf import settings
from django.test import override_settings
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch

from django.urls import reverse

from rest_framework import status
from rest_framework.test import APITransactionTestCase

from restapi import models
from restapi.utils import encrypt_with_db_secret

from .base import APITestCaseExtended
from .file_repository import (
    _REPOSITORY_CONFIGURATIONS,
    _invalid_repository_configurations,
)


class ConcurrentFileLinkMoveTests(APITransactionTestCase):
    def test_concurrent_identical_move_preserves_one_destination_link(self):
        from uuid import uuid4
        from django.db import connection

        user = models.User.objects.create(
            username="move-race@example.com",
            is_email_active=True,
            private_key_nonce="private",
            secret_key_nonce="secret",
        )
        source = models.Data_Store.objects.create(
            user=user,
            type="password",
            description="Source",
            data=b"source",
            data_nonce="source-nonce",
            secret_key="source-key",
            secret_key_nonce="source-key-nonce",
        )
        destination = models.Data_Store.objects.create(
            user=user,
            type="password",
            description="Destination",
            data=b"destination",
            data_nonce="destination-nonce",
            secret_key="destination-key",
            secret_key_nonce="destination-key-nonce",
        )
        shard = models.Fileserver_Shard.objects.create(
            title="Storage", description="Storage"
        )
        file = models.File.objects.create(
            user=user, shard=shard, size=10, chunk_count=1
        )
        identifier = uuid4()
        models.File_Link.objects.create(
            link_id=identifier, file=file, parent_datastore=source
        )
        self.client.force_authenticate(user=user)
        controller = connection.copy(alias="file-move-controller")
        inserted = False

        def execute(execute, sql, params, many, context):
            nonlocal inserted
            if (
                not inserted
                and sql.startswith("INSERT")
                and '"restapi_file_link"' in sql
            ):
                columns = [
                    column.strip().strip('"')
                    for column in sql.split("(", 1)[1].split(")", 1)[0].split(",")
                ]
                competing = list(params)
                competing[columns.index("id")] = uuid4()
                # Another connection completes the same move before this INSERT.
                # The real uniqueness constraint rejects the duplicate link.
                with controller.cursor() as cursor:
                    cursor.execute(sql, competing)
                inserted = True
            return execute(sql, params, many, context)

        try:
            with connection.execute_wrapper(execute):
                response = self.client.post(
                    reverse("file_link"),
                    {
                        "link_id": str(identifier),
                        "new_parent_datastore_id": str(destination.id),
                    },
                    format="json",
                )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(inserted)
            self.assertEqual(
                models.File_Link.objects.filter(link_id=identifier).count(), 1
            )
            saved = models.File_Link.objects.get(link_id=identifier)
            self.assertEqual(saved.file, file)
            self.assertEqual(saved.parent_datastore, destination)
            self.assertIsNone(saved.parent_share)
        finally:
            controller.close()


class FileLinkDeleteTests(APITestCaseExtended):
    """
    Tests for DELETE /file/link/ endpoint - deleting file links and ensuring proper file cleanup
    """

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "asd"
        self.test_username = "test@psono.pw"
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
        self.test_secret_key_enc = (
            "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422"
            "996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011"
            "571a48eb"
        )
        self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_private_key = (
            "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        )
        self.test_private_key_enc = (
            "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52"
            "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576"
            "a74b9b2452"
        )
        self.test_private_key_nonce = "4298a9ab3d9d5d8643dfd4445adc30301b565ab650497fb9"

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

        self.shard1 = models.Fileserver_Shard.objects.create(
            title="Some Shard Title",
            description="Some Shard Description",
        )

        self.cluster1 = models.Fileserver_Cluster.objects.create(
            title="Some Fileserver Cluster Title",
            auth_public_key="abc",
            auth_private_key="abc",
            file_size_limit=0,
        )

        self.fileserver1 = models.Fileserver_Cluster_Members.objects.create(
            create_ip="127.0.0.1",
            fileserver_cluster=self.cluster1,
            key="abc",
            public_key=binascii.hexlify(
                os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
            ).decode(),
            secret_key=binascii.hexlify(
                os.urandom(settings.USER_PUBLIC_KEY_LENGTH_BYTES)
            ).decode(),
            url="https://fs01.example.com/fileserver",
            read=True,
            write=True,
            delete_capability=True,
            valid_till=timezone.now() + timedelta(seconds=30),
        )

        models.Fileserver_Cluster_Member_Shard_Link.objects.create(
            shard=self.shard1,
            member=self.fileserver1,
            read=True,
            write=True,
            delete_capability=True,
            ip_read_whitelist=json.dumps([]),
            ip_read_blacklist=json.dumps([]),
            ip_write_whitelist=json.dumps([]),
            ip_write_blacklist=json.dumps([]),
        )

        self.test_datastore_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type",
            description="my-description",
            data=b"12345",
            data_nonce="".join(
                random.choice(string.ascii_lowercase) for _ in range(64)
            ),
            secret_key="".join(
                random.choice(string.ascii_lowercase) for _ in range(256)
            ),
            secret_key_nonce="".join(
                random.choice(string.ascii_lowercase) for _ in range(64)
            ),
        )

    def test_move_file_link_between_datastore_and_share(self):
        from uuid import uuid4

        file = models.File.objects.create(
            user=self.test_user_obj, shard=self.shard1, size=50, chunk_count=1
        )
        identifier = uuid4()
        models.File_Link.objects.create(
            link_id=identifier, file=file, parent_datastore=self.test_datastore_obj
        )
        share = models.Share.objects.create(
            user=self.test_user_obj, data=b"share", data_nonce="nonce"
        )
        models.User_Share_Right.objects.create(
            user=self.test_user_obj,
            share=share,
            read=True,
            write=True,
            grant=True,
            accepted=True,
        )
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(
            reverse("file_link"),
            {"link_id": str(identifier), "new_parent_share_id": str(share.id)},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        link = models.File_Link.objects.get(link_id=identifier)
        self.assertEqual(link.parent_share, share)
        self.assertIsNone(link.parent_datastore_id)
        response = self.client.post(
            reverse("file_link"),
            {
                "link_id": str(identifier),
                "new_parent_datastore_id": str(self.test_datastore_obj.id),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        link = models.File_Link.objects.get(link_id=identifier)
        self.assertEqual(link.parent_datastore, self.test_datastore_obj)
        self.assertIsNone(link.parent_share_id)
        file.refresh_from_db()
        self.assertIsNone(file.delete_date)

    def test_move_file_link_requires_link_id(self):
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(reverse("file_link"), {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_move_file_link_requires_destination(self):
        from uuid import uuid4

        file = models.File.objects.create(
            user=self.test_user_obj, shard=self.shard1, size=50, chunk_count=1
        )
        link = models.File_Link.objects.create(
            link_id=uuid4(), file=file, parent_datastore=self.test_datastore_obj
        )
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(
            reverse("file_link"), {"link_id": str(link.link_id)}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(models.File_Link.objects.filter(pk=link.pk).exists())

    def test_move_file_link_rejects_missing_link(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(
            reverse("file_link"),
            {
                "link_id": str(uuid4()),
                "new_parent_datastore_id": str(self.test_datastore_obj.id),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_move_file_link_requires_destination_share_write_permission(self):
        from uuid import uuid4

        file = models.File.objects.create(
            user=self.test_user_obj, shard=self.shard1, size=50, chunk_count=1
        )
        link = models.File_Link.objects.create(
            link_id=uuid4(), file=file, parent_datastore=self.test_datastore_obj
        )
        share = models.Share.objects.create(
            user=self.test_user_obj, data=b"share", data_nonce="nonce"
        )
        models.User_Share_Right.objects.create(
            user=self.test_user_obj, share=share, write=False, accepted=True
        )
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(
            reverse("file_link"),
            {"link_id": str(link.link_id), "new_parent_share_id": str(share.id)},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(models.File_Link.objects.filter(pk=link.pk).exists())

    def test_move_file_link_rejects_missing_destination_datastore(self):
        from uuid import uuid4

        file = models.File.objects.create(
            user=self.test_user_obj, shard=self.shard1, size=50, chunk_count=1
        )
        link = models.File_Link.objects.create(
            link_id=uuid4(), file=file, parent_datastore=self.test_datastore_obj
        )
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(
            reverse("file_link"),
            {"link_id": str(link.link_id), "new_parent_datastore_id": str(uuid4())},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(models.File_Link.objects.filter(pk=link.pk).exists())

    def test_move_file_link_requires_source_share_write_permission(self):
        from uuid import uuid4

        file = models.File.objects.create(
            user=self.test_user_obj, shard=self.shard1, size=50, chunk_count=1
        )
        share = models.Share.objects.create(
            user=self.test_user_obj, data=b"share", data_nonce="nonce"
        )
        models.User_Share_Right.objects.create(
            user=self.test_user_obj, share=share, write=False, accepted=True
        )
        link = models.File_Link.objects.create(
            link_id=uuid4(), file=file, parent_share=share
        )
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(
            reverse("file_link"),
            {
                "link_id": str(link.link_id),
                "new_parent_datastore_id": str(self.test_datastore_obj.id),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        link.refresh_from_db()
        self.assertEqual(link.parent_share, share)

    def test_move_file_link_requires_source_datastore_ownership(self):
        from uuid import uuid4

        file = models.File.objects.create(
            user=self.test_user_obj, shard=self.shard1, size=50, chunk_count=1
        )
        link = models.File_Link.objects.create(
            link_id=uuid4(), file=file, parent_datastore=self.test_datastore_obj
        )
        share = models.Share.objects.create(
            user=self.test_user_obj, data=b"share", data_nonce="nonce"
        )
        models.User_Share_Right.objects.create(
            user=self.test_user_obj, share=share, write=True, accepted=True
        )
        self.client.force_authenticate(user=self.test_user_obj)
        other = models.User.objects.create(
            username="other-move@example.com",
            private_key_nonce="other-private",
            secret_key_nonce="other-secret",
        )
        self.test_datastore_obj.user = other
        self.test_datastore_obj.save(update_fields=["user"])
        response = self.client.post(
            reverse("file_link"),
            {"link_id": str(link.link_id), "new_parent_share_id": str(share.id)},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        link.refresh_from_db()
        self.assertEqual(link.parent_datastore, self.test_datastore_obj)

    def test_delete_file_link_checks_share_and_datastore_ownership(self):
        from uuid import uuid4

        file = models.File.objects.create(
            user=self.test_user_obj, shard=self.shard1, size=50, chunk_count=1
        )
        share = models.Share.objects.create(
            user=self.test_user_obj, data=b"share", data_nonce="nonce"
        )
        right = models.User_Share_Right.objects.create(
            user=self.test_user_obj, share=share, write=False, accepted=True
        )
        link = models.File_Link.objects.create(
            link_id=uuid4(), file=file, parent_share=share
        )
        self.client.force_authenticate(user=self.test_user_obj)
        self.assertEqual(
            self.client.delete(
                reverse("file_link"), {"link_id": str(uuid4())}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertEqual(
            self.client.delete(
                reverse("file_link"), {"link_id": str(link.link_id)}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        right.write = True
        right.save(update_fields=["write"])
        self.assertEqual(
            self.client.delete(
                reverse("file_link"), {"link_id": str(link.link_id)}
            ).status_code,
            status.HTTP_200_OK,
        )
        other = models.User.objects.create(
            username="delete-other@example.com",
            private_key_nonce="other-private",
            secret_key_nonce="other-secret",
        )
        self.test_datastore_obj.user = other
        self.test_datastore_obj.save(update_fields=["user"])
        link = models.File_Link.objects.create(
            link_id=uuid4(), file=file, parent_datastore=self.test_datastore_obj
        )
        self.assertEqual(
            self.client.delete(
                reverse("file_link"), {"link_id": str(link.link_id)}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertTrue(models.File_Link.objects.filter(pk=link.pk).exists())

    def test_delete_file_link_with_shard_file_soft_deletes(self):
        """
        Tests that deleting the last file_link for a shard-based file soft-deletes the file
        """

        # Create a file on shard
        file = models.File.objects.create(
            shard=self.shard1,
            file_repository=None,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create file link
        link_id = "a0e98f85-6134-49e9-9bc1-3face1401bdc"
        file_link = models.File_Link.objects.create(
            link_id=link_id,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None,
        )

        url = reverse("file_link")

        data = {
            "link_id": link_id,
            "file_ids": [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify file_link was deleted
        self.assertFalse(models.File_Link.objects.filter(link_id=link_id).exists())

        # Verify file was soft-deleted (delete_date set)
        file_after = models.File.objects.get(id=file.id)
        self.assertIsNotNone(file_after.delete_date)
        self.assertLessEqual(file_after.delete_date, timezone.now())

    def _delete_repository_attachment(self, repository_type, configuration):
        repository = models.File_Repository.objects.create(
            title="Repository",
            type=repository_type,
            data=encrypt_with_db_secret(json.dumps(configuration)).encode(),
            active=True,
        )
        file = models.File.objects.create(
            user=self.test_user_obj,
            file_repository=repository,
            size=512,
            chunk_count=1,
        )
        models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=file,
            hash_checksum="a" * 128,
            position=0,
            size=512,
        )
        link = models.File_Link.objects.create(
            link_id=uuid4(), file=file, parent_datastore=self.test_datastore_obj
        )
        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(
            reverse("file_link"),
            {"link_id": str(link.link_id), "file_ids": [str(file.id)]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(models.File_Link.objects.filter(pk=link.pk).exists())
        self.assertFalse(models.File.objects.filter(pk=file.pk).exists())

    @override_settings(
        ALLOWED_OTHER_S3_ENDPOINT_URL_PREFIX=["https://objects.example.com"]
    )
    @patch("restapi.utils.gcp.RSA.importKey")
    @patch("restapi.utils.azure_blob.generate_blob_sas")
    @patch("restapi.utils.s3.boto3.client")
    @patch("requests.sessions.Session.request")
    def test_delete_rejects_unsafe_stored_repository_identifiers_before_cleanup(
        self, request, s3_client, azure_sign, gcp_key
    ):
        configurations = _invalid_repository_configurations()
        for repository_type, field, configuration in configurations:
            with self.subTest(
                provider=repository_type, field=field, value=configuration[field]
            ):
                if repository_type == "gcp_cloud_storage":
                    configuration["gcp_cloud_storage_json_key"] = json.dumps(
                        {"client_email": "test@example.com", "private_key": "fixture"}
                    )
                self._delete_repository_attachment(repository_type, configuration)
        request.assert_not_called()
        s3_client.assert_not_called()
        azure_sign.assert_not_called()
        gcp_key.assert_not_called()

    @patch("requests.delete")
    def test_delete_azure_and_gcp_cleanup_does_not_follow_redirects(self, delete):
        from Cryptodome.PublicKey import RSA

        gcp_configuration = {
            **_REPOSITORY_CONFIGURATIONS["gcp_cloud_storage"],
            "gcp_cloud_storage_json_key": json.dumps(
                {
                    "client_email": "test@example.com",
                    "private_key": RSA.generate(1024).export_key().decode(),
                }
            ),
        }
        delete.return_value.status_code = 302
        delete.return_value.headers = {"Location": "http://127.0.0.1/"}
        for repository_type, configuration, host in (
            (
                "azure_blob",
                _REPOSITORY_CONFIGURATIONS["azure_blob"],
                "account123.blob.core.windows.net",
            ),
            ("gcp_cloud_storage", gcp_configuration, "storage.googleapis.com"),
        ):
            with self.subTest(provider=repository_type):
                delete.reset_mock()
                self._delete_repository_attachment(repository_type, configuration)
                delete.assert_called_once()
                self.assertFalse(delete.call_args.kwargs["allow_redirects"])
                parsed = urlsplit(delete.call_args.args[0])
                self.assertEqual(parsed.scheme, "https")
                self.assertEqual(parsed.hostname, host)
                if repository_type == "azure_blob":
                    self.assertEqual(parse_qs(parsed.query)["sp"], ["d"])

    @override_settings(
        ALLOWED_OTHER_S3_ENDPOINT_URL_PREFIX=["https://objects.example.com"]
    )
    @patch("restapi.utils.s3.boto3.client")
    def test_delete_s3_cleanup_preserves_provider_endpoints(self, client):
        for repository_type, endpoint in (
            ("aws_s3", None),
            ("backblaze", "https://s3.us-west-004.backblazeb2.com"),
            ("do_spaces", "https://nyc3.digitaloceanspaces.com"),
            ("other_s3", "https://objects.example.com"),
        ):
            with self.subTest(provider=repository_type):
                client.reset_mock()
                self._delete_repository_attachment(
                    repository_type, _REPOSITORY_CONFIGURATIONS[repository_type]
                )
                client.assert_called_once()
                self.assertEqual(client.call_args.kwargs["endpoint_url"], endpoint)
                client.return_value.delete_object.assert_called_once()

    @patch("restapi.utils.gcs_delete")
    def test_delete_file_link_with_gcs_file_repository_hard_deletes(
        self, mock_gcs_delete
    ):
        """
        Tests that deleting the last file_link for a GCS file repository file hard-deletes
        the file and calls gcs_delete for each chunk
        """

        # Create a GCS file repository
        file_repository_data = {
            "gcp_cloud_storage_bucket": "test-bucket",
            "gcp_cloud_storage_json_key": '{"key": "value"}',
        }
        file_repository = models.File_Repository.objects.create(
            title="Test GCS Repository",
            type="gcp_cloud_storage",
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file using GCS file repository
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=None,
            chunk_count=2,
            size=1024,
            user=self.test_user_obj,
        )

        # Create chunks
        chunk1 = models.File_Chunk.objects.create(
            file=file,
            hash_checksum="abcdef123456",
            position=0,
            size=512,
            user=self.test_user_obj,
        )
        chunk2 = models.File_Chunk.objects.create(
            file=file,
            hash_checksum="fedcba654321",
            position=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create file link
        link_id = "a0e98f85-6134-49e9-9bc1-3face1401bdc"
        file_link = models.File_Link.objects.create(
            link_id=link_id,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None,
        )

        url = reverse("file_link")

        data = {
            "link_id": link_id,
            "file_ids": [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify gcs_delete was called for each chunk
        self.assertEqual(mock_gcs_delete.call_count, 2)

        # Verify file_link was deleted
        self.assertFalse(models.File_Link.objects.filter(link_id=link_id).exists())

        # Verify file was hard-deleted
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch("restapi.utils.aws_delete")
    def test_delete_file_link_with_aws_s3_file_repository(self, mock_aws_delete):
        """
        Tests that deleting file_link with AWS S3 file repository calls aws_delete
        """

        # Create an AWS S3 file repository
        file_repository_data = {
            "aws_s3_bucket": "test-aws-bucket",
            "aws_s3_region": "us-east-1",
            "aws_s3_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_s3_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }
        file_repository = models.File_Repository.objects.create(
            title="Test AWS S3 Repository",
            type="aws_s3",
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create chunk
        chunk = models.File_Chunk.objects.create(
            file=file,
            hash_checksum="abcdef123456",
            position=0,
            size=512,
            user=self.test_user_obj,
        )

        # Create file link
        link_id = "a0e98f85-6134-49e9-9bc1-3face1401bdc"
        file_link = models.File_Link.objects.create(
            link_id=link_id,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None,
        )

        url = reverse("file_link")

        data = {
            "link_id": link_id,
            "file_ids": [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify aws_delete was called
        self.assertEqual(mock_aws_delete.call_count, 1)

        # Verify file was hard-deleted
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    @patch("restapi.utils.azure_blob_delete")
    def test_delete_file_link_with_azure_blob_file_repository(self, mock_azure_delete):
        """
        Tests that deleting file_link with Azure Blob file repository calls azure_blob_delete
        """

        # Create an Azure Blob file repository
        file_repository_data = {
            "azure_blob_storage_account_name": "testaccount",
            "azure_blob_storage_account_primary_key": "test-primary-key",
            "azure_blob_storage_account_container_name": "test-container",
        }
        file_repository = models.File_Repository.objects.create(
            title="Test Azure Blob Repository",
            type="azure_blob",
            data=encrypt_with_db_secret(json.dumps(file_repository_data)).encode(),
            active=True,
        )

        # Create a file
        file = models.File.objects.create(
            shard=None,
            file_repository=file_repository,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create chunk
        chunk = models.File_Chunk.objects.create(
            file=file,
            hash_checksum="abcdef123456",
            position=0,
            size=512,
            user=self.test_user_obj,
        )

        # Create file link
        link_id = "a0e98f85-6134-49e9-9bc1-3face1401bdc"
        file_link = models.File_Link.objects.create(
            link_id=link_id,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None,
        )

        url = reverse("file_link")

        data = {
            "link_id": link_id,
            "file_ids": [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify azure_blob_delete was called
        self.assertEqual(mock_azure_delete.call_count, 1)

        # Verify file was hard-deleted
        self.assertFalse(models.File.objects.filter(id=file.id).exists())

    def test_delete_file_link_preserves_file_with_remaining_links(self):
        """
        Tests that deleting a file_link does NOT delete the file if other links still exist
        """

        # Create a file on shard
        file = models.File.objects.create(
            shard=self.shard1,
            file_repository=None,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create TWO separate datastores to allow two file links
        test_datastore2_obj = models.Data_Store.objects.create(
            user_id=self.test_user_obj.id,
            type="my-type-2",
            description="my-description-2",
            data=b"67890",
            data_nonce="".join(
                random.choice(string.ascii_lowercase) for _ in range(64)
            ),
            secret_key="".join(
                random.choice(string.ascii_lowercase) for _ in range(256)
            ),
            secret_key_nonce="".join(
                random.choice(string.ascii_lowercase) for _ in range(64)
            ),
        )

        # Create TWO file links with different link_ids (unique constraint)
        link_id1 = "a0e98f85-6134-49e9-9bc1-3face1401bdc"
        file_link1 = models.File_Link.objects.create(
            link_id=link_id1,
            file_id=file.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None,
        )

        link_id2 = "b0e98f85-6134-49e9-9bc1-3face1401bdc"
        file_link2 = models.File_Link.objects.create(
            link_id=link_id2,
            file_id=file.id,
            parent_datastore_id=test_datastore2_obj.id,
            parent_share_id=None,
        )

        url = reverse("file_link")

        # Delete only the first link
        data = {
            "link_id": link_id1,
            "file_ids": [str(file.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify first file_link was deleted
        self.assertFalse(models.File_Link.objects.filter(link_id=link_id1).exists())

        # Verify second file_link still exists
        self.assertTrue(models.File_Link.objects.filter(link_id=link_id2).exists())

        # Verify file was NOT deleted (still has a link)
        self.assertTrue(models.File.objects.filter(id=file.id).exists())
        file_after = models.File.objects.get(id=file.id)
        self.assertIsNone(file_after.delete_date)

    def test_delete_file_link_checks_orphaned_files_correctly(self):
        """
        Tests that DELETE checks file_ids parameter correctly - only deletes truly orphaned files
        """

        # Create a file on shard
        file1 = models.File.objects.create(
            shard=self.shard1,
            file_repository=None,
            secret=None,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        # Create another file that will remain linked
        file2 = models.File.objects.create(
            shard=self.shard1,
            file_repository=None,
            secret=None,
            chunk_count=1,
            size=256,
            user=self.test_user_obj,
        )

        # Create file link for file1
        link_id1 = "a0e98f85-6134-49e9-9bc1-3face1401bdc"
        file_link1 = models.File_Link.objects.create(
            link_id=link_id1,
            file_id=file1.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None,
        )

        # Create file link for file2 (different link_id)
        link_id2 = "b0e98f85-6134-49e9-9bc1-3face1401bdc"
        file_link2 = models.File_Link.objects.create(
            link_id=link_id2,
            file_id=file2.id,
            parent_datastore_id=self.test_datastore_obj.id,
            parent_share_id=None,
        )

        url = reverse("file_link")

        # Delete link_id1, but pass BOTH file IDs
        # Only file1 should be deleted (orphaned), file2 should remain (still has link_id2)
        data = {
            "link_id": link_id1,
            "file_ids": [str(file1.id), str(file2.id)],
        }

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify link1 was deleted
        self.assertFalse(models.File_Link.objects.filter(link_id=link_id1).exists())

        # Verify link2 still exists
        self.assertTrue(models.File_Link.objects.filter(link_id=link_id2).exists())

        # Verify file1 was soft-deleted (orphaned)
        file1_after = models.File.objects.get(id=file1.id)
        self.assertIsNotNone(file1_after.delete_date)

        # Verify file2 was NOT deleted (still has link)
        file2_after = models.File.objects.get(id=file2.id)
        self.assertIsNone(file2_after.delete_date)
