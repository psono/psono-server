from django.urls import reverse
from mock import patch

from rest_framework import status
from .base import APITestCaseExtended
from restapi import models
from restapi.utils import encrypt_with_db_secret

import json


def gcs_construct_signed_download_url_side_effect(bucket, json_key, hash_checksum):
    return "https://example.com/whatever", {
        "param1": "one",
        "param2": "one",
    }


class FileRepositryDownloadTest(APITestCaseExtended):
    """
    Test to file repository downloads
    """

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_email_bcrypt = "a"
        self.test_email2 = "test2@example.com"
        self.test_email_bcrypt2 = "b"
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
        self.test_secret_key_enc = (
            "77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422"
            "996e4a26de599982d531eef3098c9a531a05f75878ac0739571d6a242e6bf68c2c28eadf1011"
            "571a48eb"
        )
        self.test_secret_key_nonce = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3c"
        self.test_secret_key_nonce2 = "f580cc9900ce7ae8b6f7d2bab4627e9e689dca0f13a53e3d"
        self.test_private_key = (
            "d636f7cc20384475bdc30c3ede98f719ee09d1fd4709276103772dd9479f353c"
        )
        self.test_private_key_enc = (
            "abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52"
            "d60785eb1136803407b69729c38bb50eefdd2d24f2fa0f104990eee001866ba83704cf4f576"
            "a74b9b2452"
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
            user_sauce="af8d7c6e835a4e378655e8e11fa0b09afc2f08acf0be1d71d9fa048a2b09d2eb",
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
            user_sauce="f2b5314ccdd726c3f4deabf5efccb0de5183796a9ecc691565aff2edf8c60249",
            is_email_active=True,
        )

        self.file_repository = models.File_Repository.objects.create(
            title="Some Title",
            type="gcp_cloud_storage",
            data=encrypt_with_db_secret(
                json.dumps(
                    {
                        "gcp_cloud_storage_bucket": "psono-file-download",
                        "gcp_cloud_storage_json_key": "{}",
                    }
                )
            ).encode(),
            active=True,
        )

        self.file_repository_right = models.File_Repository_Right.objects.create(
            user=self.test_user_obj,
            file_repository=self.file_repository,
            read=True,
            write=True,
            grant=True,
            accepted=True,
        )

        self.file = models.File.objects.create(
            shard=None,
            file_repository_id=self.file_repository.id,
            chunk_count=1,
            size=512,
            user=self.test_user_obj,
        )

        self.file_transfer = models.File_Transfer.objects.create(
            user_id=self.test_user_obj.id,
            shard=None,
            file_repository=self.file_repository,
            file=self.file,
            size=512,
            size_transferred=0,
            chunk_count=1,
            chunk_count_transferred=0,
            credit=0,
            type="download",
        )
        self.file_transfer.write = True

        self.hash_checksum = "abc"
        self.file_chunk = models.File_Chunk.objects.create(
            user=self.test_user_obj,
            file=self.file,
            hash_checksum=self.hash_checksum,
            position=1,
            size=512,
        )

    def test_unknown_chunk_is_rejected_without_transfer_progress(self):
        self.client.force_authenticate(
            user=self.test_user_obj, token=self.file_transfer
        )
        response = self.client.put(
            reverse("file_repository_download"), {"hash_checksum": "abcdef"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("NO_PERMISSION_OR_NOT_EXIST", response.data["non_field_errors"])
        self.file_transfer.refresh_from_db()
        self.assertEqual(self.file_transfer.chunk_count_transferred, 0)

    def test_aws_s3_generates_real_signed_download_url(self):
        from urllib.parse import urlparse, parse_qs

        configuration = {
            "aws_s3_bucket": "bucket",
            "aws_s3_region": "us-east-1",
            "aws_s3_access_key_id": "testing",
            "aws_s3_secret_access_key": "test-secret",
        }
        self.file_repository.type = "aws_s3"
        self.file_repository.data = encrypt_with_db_secret(
            json.dumps(configuration)
        ).encode()
        self.file_repository.save(update_fields=["type", "data"])
        transfer = models.File_Transfer.objects.create(
            user=self.test_user_obj,
            file=self.file,
            file_repository=self.file_repository,
            size=512,
            size_transferred=0,
            chunk_count=1,
            chunk_count_transferred=0,
            credit=0,
            type="download",
        )
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_AUTHORIZATION=f"Filetransfer {transfer.id}")
        response = self.client.put(
            reverse("file_repository_download"), {"hash_checksum": self.hash_checksum}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        parsed = urlparse(response.data["url"])
        self.assertEqual(parsed.scheme, "https")
        self.assertIn("Signature", parse_qs(parsed.query))
        self.assertEqual(response.data["type"], "aws_s3")
        self.assertIn(self.hash_checksum, parsed.path)

    def test_azure_blob_generates_real_signed_download_url(self):
        import base64
        from urllib.parse import urlparse, parse_qs

        configuration = {
            "azure_blob_storage_account_name": "account",
            "azure_blob_storage_account_primary_key": base64.b64encode(
                bytes(range(32))
            ).decode(),
            "azure_blob_storage_account_container_name": "container",
        }
        self.file_repository.type = "azure_blob"
        self.file_repository.data = encrypt_with_db_secret(
            json.dumps(configuration)
        ).encode()
        self.file_repository.save(update_fields=["type", "data"])
        transfer = models.File_Transfer.objects.create(
            user=self.test_user_obj,
            file=self.file,
            file_repository=self.file_repository,
            size=512,
            size_transferred=0,
            chunk_count=1,
            chunk_count_transferred=0,
            credit=0,
            type="download",
        )
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_AUTHORIZATION=f"Filetransfer {transfer.id}")
        response = self.client.put(
            reverse("file_repository_download"), {"hash_checksum": self.hash_checksum}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        parsed = urlparse(response.data["url"])
        self.assertEqual(parsed.scheme, "https")
        self.assertIn("sig", parse_qs(parsed.query))
        self.assertEqual(response.data["type"], "azure_blob")
        self.assertIn(self.hash_checksum, parsed.path)

    def test_backblaze_generates_real_signed_download_url(self):
        from urllib.parse import urlparse, parse_qs

        configuration = {
            "backblaze_bucket": "bucket",
            "backblaze_region": "us-west-004",
            "backblaze_access_key_id": "testing",
            "backblaze_secret_access_key": "test-secret",
        }
        self.file_repository.type = "backblaze"
        self.file_repository.data = encrypt_with_db_secret(
            json.dumps(configuration)
        ).encode()
        self.file_repository.save(update_fields=["type", "data"])
        transfer = models.File_Transfer.objects.create(
            user=self.test_user_obj,
            file=self.file,
            file_repository=self.file_repository,
            size=512,
            size_transferred=0,
            chunk_count=1,
            chunk_count_transferred=0,
            credit=0,
            type="download",
        )
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_AUTHORIZATION=f"Filetransfer {transfer.id}")
        response = self.client.put(
            reverse("file_repository_download"), {"hash_checksum": self.hash_checksum}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        parsed = urlparse(response.data["url"])
        self.assertEqual(parsed.scheme, "https")
        self.assertIn("X-Amz-Signature", parse_qs(parsed.query))
        self.assertEqual(response.data["type"], "backblaze")
        self.assertIn(self.hash_checksum, parsed.path)

    def test_other_s3_generates_real_signed_download_url(self):
        from urllib.parse import urlparse, parse_qs

        configuration = {
            "other_s3_bucket": "bucket",
            "other_s3_region": "us-east-1",
            "other_s3_access_key_id": "testing",
            "other_s3_secret_access_key": "test-secret",
            "other_s3_endpoint_url": "https://objects.example.com",
        }
        self.file_repository.type = "other_s3"
        self.file_repository.data = encrypt_with_db_secret(
            json.dumps(configuration)
        ).encode()
        self.file_repository.save(update_fields=["type", "data"])
        transfer = models.File_Transfer.objects.create(
            user=self.test_user_obj,
            file=self.file,
            file_repository=self.file_repository,
            size=512,
            size_transferred=0,
            chunk_count=1,
            chunk_count_transferred=0,
            credit=0,
            type="download",
        )
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_AUTHORIZATION=f"Filetransfer {transfer.id}")
        response = self.client.put(
            reverse("file_repository_download"), {"hash_checksum": self.hash_checksum}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        parsed = urlparse(response.data["url"])
        self.assertEqual(parsed.scheme, "https")
        self.assertIn("Signature", parse_qs(parsed.query))
        self.assertEqual(response.data["type"], "other_s3")
        self.assertIn(self.hash_checksum, parsed.path)

    def test_do_spaces_generates_real_signed_download_url(self):
        from urllib.parse import urlparse, parse_qs

        configuration = {
            "do_space": "space",
            "do_region": "nyc3",
            "do_key": "testing",
            "do_secret": "test-secret",
        }
        self.file_repository.type = "do_spaces"
        self.file_repository.data = encrypt_with_db_secret(
            json.dumps(configuration)
        ).encode()
        self.file_repository.save(update_fields=["type", "data"])
        transfer = models.File_Transfer.objects.create(
            user=self.test_user_obj,
            file=self.file,
            file_repository=self.file_repository,
            size=512,
            size_transferred=0,
            chunk_count=1,
            chunk_count_transferred=0,
            credit=0,
            type="download",
        )
        self.client.force_authenticate(user=None)
        self.client.credentials(HTTP_AUTHORIZATION=f"Filetransfer {transfer.id}")
        response = self.client.put(
            reverse("file_repository_download"), {"hash_checksum": self.hash_checksum}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        parsed = urlparse(response.data["url"])
        self.assertEqual(parsed.scheme, "https")
        self.assertIn("X-Amz-Signature", parse_qs(parsed.query))
        self.assertEqual(response.data["type"], "do_spaces")
        self.assertIn(self.hash_checksum, parsed.path)

    def test_get(self):
        """
        Tests GET on file repository download
        """

        url = reverse("file_repository_download")

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_get_unauthenticated(self):
        """
        Tests GET on file repository download unauthenticated
        """

        url = reverse("file_repository_download")

        data = {}

        # self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_post(self):
        """
        Tests POST on file repository download
        """

        url = reverse("file_repository_download")

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_post_unauthenticated(self):
        """
        Tests POST on file repository download unauthentiated
        """

        url = reverse("file_repository_download")

        data = {}

        # self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete(self):
        """
        Tests DELETE on file repository download
        """

        url = reverse("file_repository_download")

        data = {}

        self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_unauthenticated(self):
        """
        Tests DELETE on file repository download unauthentiated
        """

        url = reverse("file_repository_download")

        data = {}

        # self.client.force_authenticate(user=self.test_user_obj)
        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch(
        "restapi.views.file_repository_download.gcs_construct_signed_download_url",
        side_effect=gcs_construct_signed_download_url_side_effect,
    )
    def test_success(self, fake_gcs_construct_signed_download_url):
        """
        Tests a file repository download successfully
        """

        url = reverse("file_repository_download")

        data = {
            "chunk_size": 512,
            "chunk_position": 0,
            "hash_checksum": self.hash_checksum,
        }

        self.client.force_authenticate(
            user=self.file_transfer.user, token=self.file_transfer
        )
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data,
            {
                "type": "gcp_cloud_storage",
                "url": "https://example.com/whatever?param1=one&param2=one",
            },
        )

    @patch(
        "restapi.views.file_repository_download.gcs_construct_signed_download_url",
        side_effect=gcs_construct_signed_download_url_side_effect,
    )
    def test_upload_transfer_is_rejected(self, fake_gcs_construct_signed_download_url):
        self.file_transfer.type = "upload"
        self.file_transfer.save(update_fields=["type", "write_date"])

        response = self.client.put(
            reverse("file_repository_download"),
            {"hash_checksum": self.hash_checksum},
            HTTP_AUTHORIZATION=f"Filetransfer {self.file_transfer.id}",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"detail": "FILE_TRANSFER_TYPE_INVALID"})
        fake_gcs_construct_signed_download_url.assert_not_called()

    @patch(
        "restapi.views.file_repository_download.gcs_construct_signed_download_url",
        side_effect=gcs_construct_signed_download_url_side_effect,
    )
    def test_malformed_checksum(self, fake_gcs_construct_signed_download_url):
        """
        Tests a file repository download with a malformed checksum that isn't hex
        """

        url = reverse("file_repository_download")

        data = {
            "chunk_size": 512,
            "chunk_position": 0,
            "hash_checksum": "xyz",
        }

        self.client.force_authenticate(
            user=self.file_transfer.user, token=self.file_transfer
        )
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "restapi.views.file_repository_download.gcs_construct_signed_download_url",
        side_effect=gcs_construct_signed_download_url_side_effect,
    )
    def test_chunk_count_exceeded(self, fake_gcs_construct_signed_download_url):
        """
        Tests a file repository download with a file transfer that has already been completed by chunk count
        """
        self.file_transfer.chunk_count_transferred = self.file_transfer.chunk_count
        self.file_transfer.save()

        url = reverse("file_repository_download")

        data = {
            "chunk_size": 512,
            "chunk_position": 0,
            "hash_checksum": self.hash_checksum,
        }

        self.client.force_authenticate(
            user=self.file_transfer.user, token=self.file_transfer
        )
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "restapi.views.file_repository_download.gcs_construct_signed_download_url",
        side_effect=gcs_construct_signed_download_url_side_effect,
    )
    def test_chunk_size_exceeded(self, fake_gcs_construct_signed_download_url):
        """
        Tests a file repository download with a file transfer that has already been completed by file size
        """
        self.file_transfer.size_transferred = self.file_transfer.size
        self.file_transfer.save()

        url = reverse("file_repository_download")

        data = {
            "chunk_size": 512,
            "chunk_position": 0,
            "hash_checksum": self.hash_checksum,
        }

        self.client.force_authenticate(
            user=self.file_transfer.user, token=self.file_transfer
        )
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_unauthenticated(self):
        """
        Tests a file repository download unauthenticated
        """

        url = reverse("file_repository_download")

        data = {
            "chunk_size": 512,
            "chunk_position": 0,
            "hash_checksum": self.hash_checksum,
        }

        # self.client.force_authenticate(user=self.file_transfer.user, token=self.file_transfer)
        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
