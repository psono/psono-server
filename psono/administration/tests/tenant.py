from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from django.db import connection, connections
from rest_framework.test import APIClient, APITransactionTestCase


class ConcurrentTenantTests(APITransactionTestCase):
    def setUp(self):
        self.admin = models.User.objects.create(
            username="race-admin@example.com",
            private_key_nonce="private",
            secret_key_nonce="secret",
            is_superuser=True,
            is_email_active=True,
        )

    def perform_concurrent_requests(self, method, urls):
        barrier = Barrier(2)
        table = models.Tenant._meta.db_table
        operation = "INSERT" if method == "post" else "UPDATE"

        def request(url):
            def execute(execute, sql, params, many, context):
                if sql.startswith(operation) and f'"{table}"' in sql:
                    barrier.wait(timeout=10)
                return execute(sql, params, many, context)

            try:
                client = APIClient()
                client.force_authenticate(user=self.admin)
                with connection.execute_wrapper(execute):
                    return getattr(client, method)(
                        url, {"name": "Concurrent tenant"}, format="json"
                    )
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(request, urls))
        self.assertEqual(
            sorted(response.status_code for response in results),
            [200 if method == "put" else 201, 400],
        )
        self.assertEqual(
            models.Tenant.objects.filter(name="Concurrent tenant").count(), 1
        )

    def test_concurrent_tenant_creation_handles_unique_constraint(self):
        url = reverse("admin_tenant")
        self.perform_concurrent_requests("post", [url, url])

    def test_concurrent_tenant_rename_handles_unique_constraint(self):
        tenants = [
            models.Tenant.objects.create(name=name) for name in ("First", "Second")
        ]
        urls = [
            reverse("admin_tenant", kwargs={"tenant_id": tenant.id})
            for tenant in tenants
        ]
        self.perform_concurrent_requests("put", urls)


class AdministrativeTenantTests(AdministrativeAccessTestCase):
    def test_tenant_create_detail_update_and_delete(self):
        self.client.force_authenticate(user=self.superuser)
        url = reverse("admin_tenant")
        response = self.client.post(
            url, {"name": "Created tenant", "description": "Initial"}
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        tenant = models.Tenant.objects.get(name="Created tenant")
        detail = reverse("admin_tenant", kwargs={"tenant_id": tenant.id})
        group = models.Group.objects.create(name="Tenant group", public_key="key")
        models.TenantGroupMembership.objects.create(
            tenant=tenant, group=group, created_by=self.superuser
        )
        models.TenantUserMembership.objects.create(
            tenant=tenant, user=self.user_a, created_by=self.superuser
        )
        response = self.client.get(detail)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response = self.client.put(
            detail, {"name": tenant.name, "description": "Updated", "is_active": False}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tenant.refresh_from_db()
        self.assertFalse(tenant.is_active)
        self.assertEqual(tenant.description, "Updated")
        self.assertEqual(
            self.client.delete(detail).status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertTrue(models.Tenant.objects.filter(pk=tenant.id).exists())
        models.TenantGroupMembership.objects.filter(tenant=tenant).delete()
        models.TenantUserMembership.objects.filter(tenant=tenant).delete()
        self.assertEqual(self.client.delete(detail).status_code, status.HTTP_200_OK)
        self.assertFalse(models.Tenant.objects.filter(pk=tenant.id).exists())
        self.assertTrue(models.User.objects.filter(pk=self.user_a.id).exists())
        self.assertTrue(models.Group.objects.filter(pk=group.id).exists())

    def test_detail_rejects_missing_tenant(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        detail = reverse("admin_tenant", kwargs={"tenant_id": uuid4()})
        self.assertEqual(
            self.client.get(detail).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_update_rejects_missing_tenant(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        detail = reverse("admin_tenant", kwargs={"tenant_id": uuid4()})
        self.assertEqual(
            self.client.put(detail, {}).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_delete_rejects_missing_tenant(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        detail = reverse("admin_tenant", kwargs={"tenant_id": uuid4()})
        self.assertEqual(
            self.client.delete(detail).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_list_rejects_non_numeric_page(self):
        self.client.force_authenticate(user=self.superuser)
        self.assertEqual(
            self.client.get(reverse("admin_tenant"), {"page": "invalid"}).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_list_rejects_negative_page(self):
        self.client.force_authenticate(user=self.superuser)
        self.assertEqual(
            self.client.get(reverse("admin_tenant"), {"page": "-1"}).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_list_rejects_zero_page_size(self):
        self.client.force_authenticate(user=self.superuser)
        self.assertEqual(
            self.client.get(reverse("admin_tenant"), {"page_size": "0"}).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_list_rejects_unknown_ordering(self):
        self.client.force_authenticate(user=self.superuser)
        self.assertEqual(
            self.client.get(
                reverse("admin_tenant"), {"ordering": "invalid"}
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_list_returns_empty_page_for_out_of_range_page_number(self):
        self.client.force_authenticate(user=self.superuser)
        url = reverse("admin_tenant")
        response = self.client.get(url, {"page_size": 1, "page": 100})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["tenants"], [])

    def test_list_rejects_non_superuser(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(reverse("admin_tenant"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_detail_rejects_non_superuser(self):
        detail_url = reverse("admin_tenant", kwargs={"tenant_id": self.tenant_b.id})
        self.client.force_authenticate(user=self.delegated_admin)
        self.assertEqual(
            self.client.get(detail_url).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_creation_rejects_non_superuser(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.post(
            reverse("admin_tenant"), {"name": "Forbidden Tenant"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(models.Tenant.objects.filter(name="Forbidden Tenant").exists())

    def test_update_rejects_non_superuser(self):
        self.client.force_authenticate(user=self.delegated_admin)
        detail_url = reverse("admin_tenant", kwargs={"tenant_id": self.tenant_b.id})
        response = self.client.put(detail_url, {"name": "Forbidden Update"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.tenant_b.refresh_from_db()
        self.assertEqual(self.tenant_b.name, "Tenant B")

    def test_delete_rejects_non_superuser(self):
        self.client.force_authenticate(user=self.delegated_admin)
        detail_url = reverse("admin_tenant", kwargs={"tenant_id": self.tenant_b.id})
        self.assertEqual(
            self.client.delete(detail_url).status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertTrue(models.Tenant.objects.filter(pk=self.tenant_b.id).exists())

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
