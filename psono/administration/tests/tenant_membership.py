from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase, create_user


class TenantMembershipTests(AdministrativeAccessTestCase):
    def test_tenant_membership_methods_are_superuser_only(self):
        data = {"tenant_id": self.tenant_a.id, "user_id": self.user_b.id}
        self.client.force_authenticate(user=self.delegated_admin)

        response = self.client.post(reverse("admin_tenant_membership"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.delete(reverse("admin_tenant_membership"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.assertFalse(
            models.TenantUserMembership.objects.filter(
                tenant=self.tenant_a, user=self.user_b
            ).exists()
        )

    def test_superuser_can_add_and_remove_tenant_membership(self):
        data = {"tenant_id": self.tenant_a.id, "user_id": self.user_b.id}
        self.client.force_authenticate(user=self.superuser)

        response = self.client.post(reverse("admin_tenant_membership"), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.delete(reverse("admin_tenant_membership"), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(
            models.TenantUserMembership.objects.filter(
                tenant=self.tenant_a, user=self.user_b
            ).exists()
        )

    def test_default_user_tenants_are_assigned(self):
        with self.settings(
            DEFAULT_USER_TENANTS=[str(self.tenant_a.id), str(self.tenant_b.id)]
        ):
            user = create_user("default-tenant-user")

        tenant_ids = set(
            models.TenantUserMembership.objects.filter(user=user).values_list(
                "tenant_id", flat=True
            )
        )
        self.assertEqual(tenant_ids, {self.tenant_a.id, self.tenant_b.id})

    def test_default_group_tenants_are_assigned(self):
        with self.settings(
            DEFAULT_GROUP_TENANTS=[str(self.tenant_a.id), str(self.tenant_b.id)]
        ):
            group = models.Group.objects.create(
                name="Default Tenant Group", public_key="public-key"
            )

        tenant_ids = set(
            models.TenantGroupMembership.objects.filter(group=group).values_list(
                "tenant_id", flat=True
            )
        )
        self.assertEqual(tenant_ids, {self.tenant_a.id, self.tenant_b.id})
