from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase


class AdministrativeTenantTests(AdministrativeAccessTestCase):
    def test_all_tenant_methods_are_superuser_only(self):
        detail_url = reverse("admin_tenant", kwargs={"tenant_id": self.tenant_b.id})
        requests = (
            ("get", reverse("admin_tenant"), None),
            ("get", detail_url, None),
            ("post", reverse("admin_tenant"), {"name": "Forbidden Tenant"}),
            ("put", detail_url, {"name": "Forbidden Update"}),
            ("delete", detail_url, None),
        )
        self.client.force_authenticate(user=self.delegated_admin)

        for method, url, data in requests:
            with self.subTest(method=method, url=url):
                response = getattr(self.client, method)(url, data or {})
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.tenant_b.refresh_from_db()
        self.assertEqual(self.tenant_b.name, "Tenant B")
        self.assertFalse(models.Tenant.objects.filter(name="Forbidden Tenant").exists())

    def test_tenant_management_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(reverse("admin_tenant"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(reverse("admin_tenant"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["tenants"]), 2)

    def test_tenant_list_supports_server_side_search_and_pagination(self):
        self.client.force_authenticate(user=self.superuser)

        response = self.client.get(
            reverse("admin_tenant"),
            {"search": "Tenant B", "page_size": 5, "page": 0},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(
            [tenant["id"] for tenant in response.data["tenants"]],
            [self.tenant_b.id],
        )

        response = self.client.get(
            reverse("admin_tenant"),
            {"page_size": 1, "page": 0, "ordering": "-name"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 2)
        self.assertEqual(len(response.data["tenants"]), 1)
        self.assertEqual(response.data["tenants"][0]["id"], self.tenant_b.id)

    def test_tenant_name_validation_returns_bad_request(self):
        self.client.force_authenticate(user=self.superuser)
        url = reverse("admin_tenant")

        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.post(url, {"name": self.tenant_a.name})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        tenant_c = models.Tenant.objects.create(name="Tenant C")
        response = self.client.put(
            reverse("admin_tenant", kwargs={"tenant_id": tenant_c.id}),
            {"name": self.tenant_a.name},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
