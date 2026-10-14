from uuid import uuid4

from django.urls import reverse
from rest_framework import status
from restapi import models
from .base import APITestCaseExtended


class FileRepositoryRightAcceptTest(APITestCaseExtended):
    def setUp(self):
        self.user = models.User.objects.create(
            username="accept@example.com",
            private_key_nonce="private",
            secret_key_nonce="secret",
            is_email_active=True,
        )
        self.other_user = models.User.objects.create(
            username="other@example.com",
            private_key_nonce="other-private",
            secret_key_nonce="other-secret",
            is_email_active=True,
        )
        self.repository = models.File_Repository.objects.create(
            title="Repository", type="gcp_cloud_storage", data=b"{}"
        )
        self.right = models.File_Repository_Right.objects.create(
            user=self.user, file_repository=self.repository, accepted=False
        )
        self.url = reverse("file_repository_right_accept")
        self.client.force_authenticate(user=self.user)

    def test_acceptance_is_persisted(self):
        response = self.client.post(
            self.url, {"file_repository_right_id": str(self.right.id)}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.right.refresh_from_db()
        self.assertTrue(self.right.accepted)

    def test_accepting_an_already_accepted_right_is_idempotent(self):
        self.right.accepted = True
        self.right.save(update_fields=["accepted"])
        response = self.client.post(
            self.url, {"file_repository_right_id": str(self.right.id)}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.right.refresh_from_db()
        self.assertTrue(self.right.accepted)
        self.assertEqual(models.File_Repository_Right.objects.count(), 1)

    def test_foreign_right_is_rejected(self):
        self.right.user = self.other_user
        self.right.save(update_fields=["user"])
        response = self.client.post(
            self.url, {"file_repository_right_id": str(self.right.id)}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.right.refresh_from_db()
        self.assertFalse(self.right.accepted)

    def test_missing_right_is_rejected(self):
        response = self.client.post(
            self.url, {"file_repository_right_id": str(uuid4())}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.right.refresh_from_db()
        self.assertFalse(self.right.accepted)

    def test_malformed_identifier_is_rejected(self):
        response = self.client.post(self.url, {"file_repository_right_id": "invalid"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_identifier_is_rejected(self):
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_metadata_describes_acceptance_identifier(self):
        response = self.client.options(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("file_repository_right_id", response.data["actions"]["POST"])

    def test_get_is_not_supported(self):
        self.assertEqual(
            self.client.get(self.url).status_code, status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def test_put_is_not_supported(self):
        self.assertEqual(
            self.client.put(self.url, {}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def test_delete_is_not_supported(self):
        self.assertEqual(
            self.client.delete(self.url).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def test_authentication_is_required(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(
            self.url, {"file_repository_right_id": str(self.right.id)}
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
