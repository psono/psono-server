from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from django.db import connection, connections
from rest_framework.test import APIClient, APITransactionTestCase


class ConcurrentAdministrativeRoleTests(APITransactionTestCase):
    def setUp(self):
        self.admin = models.User.objects.create(
            username="race-admin@example.com",
            private_key_nonce="private",
            secret_key_nonce="secret",
            is_superuser=True,
            is_email_active=True,
        )

    def perform_concurrent_requests(self, method, urls, payload):
        barrier = Barrier(2)
        table = models.AdministrativeRole._meta.db_table
        operation = "INSERT" if method == "post" else "UPDATE"

        def request(url):
            def execute(execute, sql, params, many, context):
                if sql.startswith(operation) and f'"{table}"' in sql:
                    barrier.wait(timeout=10)
                return execute(sql, params, many, context)

            try:
                client = APIClient()
                client.force_authenticate(user=self.admin)
                # Coordinate real writes after validation; every query still
                # executes against the real database and its unique constraint.
                with connection.execute_wrapper(execute):
                    return getattr(client, method)(url, payload, format="json")
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(request, urls))
        self.assertEqual(
            sorted(response.status_code for response in results),
            [200 if method == "put" else 201, 400],
        )
        self.assertEqual(
            models.AdministrativeRole.objects.filter(name=payload["name"]).count(), 1
        )

    def test_concurrent_role_creation_handles_unique_constraint(self):
        url = reverse("admin_administrative_role")
        self.perform_concurrent_requests(
            "post", [url, url], {"name": "Concurrent role"}
        )

    def test_concurrent_role_rename_handles_unique_constraint(self):
        roles = [
            models.AdministrativeRole.objects.create(name=name)
            for name in ("First", "Second")
        ]
        urls = [
            reverse("admin_administrative_role", kwargs={"role_id": role.id})
            for role in roles
        ]
        self.perform_concurrent_requests("put", urls, {"name": "Concurrent role"})


class AdministrativeRoleTests(AdministrativeAccessTestCase):
    def test_custom_role_create_detail_update_and_delete(self):
        self.client.force_authenticate(user=self.superuser)
        url = reverse("admin_administrative_role")
        response = self.client.post(
            url,
            {
                "name": "Custom role",
                "description": "Initial",
                "capabilities": ["users.read", "users.read"],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role = models.AdministrativeRole.objects.get(name="Custom role")
        self.assertEqual(
            list(role.capabilities.values_list("capability", flat=True)), ["users.read"]
        )
        detail = reverse("admin_administrative_role", kwargs={"role_id": role.id})
        self.assertEqual(self.client.get(detail).status_code, status.HTTP_200_OK)
        response = self.client.put(
            detail,
            {
                "name": role.name,
                "description": "Updated",
                "is_active": False,
                "capabilities": ["groups.read"],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        role.refresh_from_db()
        self.assertEqual(role.description, "Updated")
        self.assertFalse(role.is_active)
        self.assertEqual(
            list(role.capabilities.values_list("capability", flat=True)),
            ["groups.read"],
        )
        self.assertEqual(self.client.delete(detail).status_code, status.HTTP_200_OK)
        self.assertFalse(models.AdministrativeRole.objects.filter(pk=role.id).exists())
        self.assertEqual(
            self.client.post(url, {"name": "Empty role"}).status_code,
            status.HTTP_201_CREATED,
        )

    def test_role_creation_requires_name(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(reverse("admin_administrative_role"), {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_role_creation_rejects_invalid_capability(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_administrative_role"),
            {"name": "Invalid", "capabilities": ["invalid"]},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(
            models.AdministrativeRole.objects.filter(name="Invalid").exists()
        )

    def test_role_detail_rejects_missing_role(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        self.assertEqual(
            self.client.get(
                reverse("admin_administrative_role", kwargs={"role_id": uuid4()})
            ).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_role_update_rejects_global_capability_for_tenant_assignment(self):
        self.client.force_authenticate(user=self.superuser)
        detail = reverse("admin_administrative_role", kwargs={"role_id": self.role.id})
        response = self.client.put(detail, {"capabilities": ["fileservers.manage"]})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("ROLE_REQUIRES_GLOBAL_SCOPE", response.data["non_field_errors"])
        self.assertEqual(
            list(self.role.capabilities.values_list("capability", flat=True)),
            ["users.read"],
        )

    def test_role_delete_rejects_assigned_role(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.delete(
            reverse("admin_administrative_role", kwargs={"role_id": self.role.id})
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(
            models.AdministrativeRole.objects.filter(pk=self.role.id).exists()
        )

    def test_role_list_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(reverse("admin_administrative_role"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_role_detail_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(
            reverse("admin_administrative_role", kwargs={"role_id": self.role.id})
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_role_creation_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.post(
            reverse("admin_administrative_role"), {"name": "Forbidden Role"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(
            models.AdministrativeRole.objects.filter(name="Forbidden Role").exists()
        )

    def test_role_update_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.put(
            reverse("admin_administrative_role", kwargs={"role_id": self.role.id}),
            {"name": "Forbidden Update"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.role.refresh_from_db()
        self.assertEqual(self.role.name, "Tenant User Reader")

    def test_role_delete_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.delete(
            reverse("admin_administrative_role", kwargs={"role_id": self.role.id})
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(
            models.AdministrativeRole.objects.filter(pk=self.role.id).exists()
        )

    def test_default_role_system_keys(self):
        self.assertEqual(
            set(
                models.AdministrativeRole.objects.filter(is_system=True).values_list(
                    "system_key", flat=True
                )
            ),
            {
                "full_administrator",
                "user_administrator",
                "group_administrator",
                "read_only_auditor",
                "fileserver_administrator",
            },
        )

    def test_full_administrator_capability_bundle(self):
        role = models.AdministrativeRole.objects.get(system_key="full_administrator")
        self.assertTrue(role.is_full_access)
        self.assertFalse(role.capabilities.exists())

    def test_user_administrator_capability_bundle(self):
        role = models.AdministrativeRole.objects.get(system_key="user_administrator")
        self.assertFalse(role.is_full_access)
        self.assertEqual(
            set(role.capabilities.values_list("capability", flat=True)),
            {
                "users.read",
                "users.create",
                "users.update",
                "users.delete",
                "users.sessions.read",
                "users.sessions.delete",
                "users.mfa.delete",
                "users.recovery.read",
                "users.recovery.delete",
                "users.link_shares.delete",
                "security_reports.read",
            },
        )

    def test_group_administrator_capability_bundle(self):
        role = models.AdministrativeRole.objects.get(system_key="group_administrator")
        self.assertFalse(role.is_full_access)
        self.assertEqual(
            set(role.capabilities.values_list("capability", flat=True)),
            {
                "groups.read",
                "groups.update",
                "groups.delete",
                "groups.memberships.read",
                "groups.memberships.manage",
                "groups.shares.manage",
            },
        )

    def test_read_only_auditor_capability_bundle(self):
        role = models.AdministrativeRole.objects.get(system_key="read_only_auditor")
        self.assertFalse(role.is_full_access)
        self.assertEqual(
            set(role.capabilities.values_list("capability", flat=True)),
            {
                "system.read",
                "statistics.read",
                "users.read",
                "users.sessions.read",
                "users.recovery.read",
                "security_reports.read",
                "groups.read",
                "groups.memberships.read",
                "fileservers.read",
            },
        )

    def test_fileserver_administrator_capability_bundle(self):
        role = models.AdministrativeRole.objects.get(
            system_key="fileserver_administrator"
        )
        self.assertFalse(role.is_full_access)
        self.assertEqual(
            set(role.capabilities.values_list("capability", flat=True)),
            {
                "fileservers.read",
                "fileservers.manage",
            },
        )

    def test_role_list_query_count_is_constant(self):
        second_role = models.AdministrativeRole.objects.create(name="Second Role")
        models.AdministrativeRoleCapability.objects.create(
            role=second_role, capability="groups.read"
        )
        self.client.force_authenticate(user=self.superuser)

        with self.assertNumQueries(2):
            response = self.client.get(reverse("admin_administrative_role"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["roles"]), 2)

    def test_only_custom_roles_can_be_modified(self):
        self.client.force_authenticate(user=self.superuser)
        default_role = models.AdministrativeRole.objects.get(
            system_key="user_administrator"
        )
        default_url = reverse(
            "admin_administrative_role", kwargs={"role_id": default_role.id}
        )

        response = self.client.put(default_url, {"name": "Changed Default Role"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.delete(default_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        default_role.refresh_from_db()
        self.assertEqual(default_role.name, "User Administrator")

        custom_url = reverse(
            "admin_administrative_role", kwargs={"role_id": self.role.id}
        )
        response = self.client.put(custom_url, {"name": "Renamed Custom Role"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.role.refresh_from_db()
        self.assertEqual(self.role.name, "Renamed Custom Role")

    def test_role_name_collision_validation_returns_bad_request(self):
        self.client.force_authenticate(user=self.superuser)
        role_url = reverse("admin_administrative_role")

        response = self.client.post(role_url, {"name": self.role.name})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        second_role = models.AdministrativeRole.objects.create(name="Second Role")
        response = self.client.put(
            reverse("admin_administrative_role", kwargs={"role_id": second_role.id}),
            {"name": self.role.name},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
