from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase


class AdministrativeAuthorizationTests(AdministrativeAccessTestCase):
    def test_global_capabilities_dominate_tenant_scopes_and_ignore_retired_codes(self):
        models.AdministrativeRoleCapability.objects.create(
            role=self.role, capability="retired.capability"
        )
        self.tenant_b.is_active = False
        self.tenant_b.save(update_fields=["is_active"])
        models.AdministrativeRoleAssignmentTenant.objects.create(
            assignment=self.assignment, tenant=self.tenant_b
        )
        full = models.AdministrativeRole.objects.create(
            name="Global full access", is_full_access=True
        )
        models.AdministrativeRoleAssignment.objects.create(
            role=full, user=self.delegated_admin, is_global=True
        )
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(reverse("admin_authorization"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn("retired.capability", response.data["capabilities"])
        self.assertTrue(response.data["capabilities"]["users.read"]["global"])
        self.assertEqual(response.data["capabilities"]["users.read"]["tenant_ids"], [])

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
