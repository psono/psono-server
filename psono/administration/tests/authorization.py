from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase


class AdministrativeAuthorizationTests(AdministrativeAccessTestCase):
    def test_superuser_authorization_ignores_session_read_flag(self):
        token = models.Token.objects.create(
            user=self.superuser, read=False, write=False
        )
        self.client.force_authenticate(user=self.superuser, token=token)

        response = self.client.get(reverse("admin_authorization"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["is_superuser"])

    def test_authorization_returns_effective_tenant_scope(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(reverse("admin_authorization"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["is_superuser"])
        self.assertEqual(
            response.data["capabilities"]["users.read"]["tenant_ids"],
            [str(self.tenant_a.id)],
        )
