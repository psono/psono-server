from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase, create_user


class TenantMembershipTests(AdministrativeAccessTestCase):
    def test_add_membership_rejects_missing_tenant(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_tenant_membership"),
            {"tenant_id": str(uuid4()), "user_id": str(self.user_a.id)},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            models.TenantUserMembership.objects.filter(user=self.user_a).count(), 1
        )

    def test_remove_membership_rejects_missing_tenant(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(
            reverse("admin_tenant_membership"),
            {"tenant_id": str(uuid4()), "user_id": str(self.user_a.id)},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(
            models.TenantUserMembership.objects.filter(
                user=self.user_a, tenant=self.tenant_a
            ).exists()
        )

    def test_add_membership_requires_target(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_tenant_membership"), {"tenant_id": str(self.tenant_a.id)}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remove_membership_requires_target(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(
            reverse("admin_tenant_membership"), {"tenant_id": str(self.tenant_a.id)}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_add_membership_rejects_user_and_group_together(self):
        group = models.Group.objects.create(name="Target group", public_key="key")
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_tenant_membership"),
            {
                "tenant_id": str(self.tenant_a.id),
                "user_id": str(self.user_a.id),
                "group_id": str(group.id),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(
            models.TenantGroupMembership.objects.filter(group=group).exists()
        )

    def test_remove_membership_rejects_user_and_group_together(self):
        group = models.Group.objects.create(name="Target group", public_key="key")
        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(
            reverse("admin_tenant_membership"),
            {
                "tenant_id": str(self.tenant_a.id),
                "user_id": str(self.user_a.id),
                "group_id": str(group.id),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(
            models.TenantUserMembership.objects.filter(
                user=self.user_a, tenant=self.tenant_a
            ).exists()
        )

    def test_add_membership_rejects_missing_user(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_tenant_membership"),
            {"tenant_id": str(self.tenant_a.id), "user_id": str(uuid4())},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remove_membership_rejects_missing_user(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(
            reverse("admin_tenant_membership"),
            {"tenant_id": str(self.tenant_a.id), "user_id": str(uuid4())},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_add_membership_rejects_missing_group(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_tenant_membership"),
            {"tenant_id": str(self.tenant_a.id), "group_id": str(uuid4())},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remove_membership_rejects_missing_group(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(
            reverse("admin_tenant_membership"),
            {"tenant_id": str(self.tenant_a.id), "group_id": str(uuid4())},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_add_group_membership(self):
        group = models.Group.objects.create(name="Target group", public_key="key")
        self.client.force_authenticate(user=self.superuser)
        data = {"tenant_id": str(self.tenant_a.id), "group_id": str(group.id)}
        self.assertEqual(
            self.client.post(reverse("admin_tenant_membership"), data).status_code,
            status.HTTP_201_CREATED,
        )
        self.assertTrue(
            models.TenantGroupMembership.objects.filter(
                group=group, tenant=self.tenant_a
            ).exists()
        )

    def test_remove_group_membership(self):
        group = models.Group.objects.create(name="Target group", public_key="key")
        models.TenantGroupMembership.objects.create(group=group, tenant=self.tenant_a)
        self.client.force_authenticate(user=self.superuser)
        data = {"tenant_id": str(self.tenant_a.id), "group_id": str(group.id)}
        self.assertEqual(
            self.client.delete(reverse("admin_tenant_membership"), data).status_code,
            status.HTTP_200_OK,
        )
        self.assertFalse(
            models.TenantGroupMembership.objects.filter(
                group=group, tenant=self.tenant_a
            ).exists()
        )

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
