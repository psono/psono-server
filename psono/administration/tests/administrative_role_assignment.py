from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from django.db import connection, connections
from rest_framework.test import APIClient, APITransactionTestCase


class ConcurrentAdministrativeAssignmentTests(APITransactionTestCase):
    def setUp(self):
        self.admin = models.User.objects.create(
            username="race-admin@example.com",
            private_key_nonce="private",
            secret_key_nonce="secret",
            is_superuser=True,
            is_email_active=True,
        )
        self.user = models.User.objects.create(
            username="race-user@example.com",
            private_key_nonce="other-private",
            secret_key_nonce="other-secret",
        )
        self.role = models.AdministrativeRole.objects.create(name="Target role")

    def perform_concurrent_requests(self, method, urls):
        barrier = Barrier(2)
        table = models.AdministrativeRoleAssignment._meta.db_table
        operation = "INSERT" if method == "post" else "UPDATE"
        payload = {
            "role_id": str(self.role.id),
            "user_id": str(self.user.id),
            "is_global": True,
            "tenant_ids": [],
        }

        def request(url):
            def execute(execute, sql, params, many, context):
                if sql.startswith(operation) and f'"{table}"' in sql:
                    barrier.wait(timeout=10)
                return execute(sql, params, many, context)

            try:
                client = APIClient()
                client.force_authenticate(user=self.admin)
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
            models.AdministrativeRoleAssignment.objects.filter(
                role=self.role, user=self.user
            ).count(),
            1,
        )

    def test_concurrent_assignment_creation_handles_unique_constraint(self):
        url = reverse("admin_administrative_role_assignment")
        self.perform_concurrent_requests("post", [url, url])

    def test_concurrent_assignment_update_handles_unique_constraint(self):
        roles = [
            models.AdministrativeRole.objects.create(name=name)
            for name in ("First", "Second")
        ]
        assignments = [
            models.AdministrativeRoleAssignment.objects.create(
                role=role, user=self.user, is_global=True
            )
            for role in roles
        ]
        urls = [
            reverse(
                "admin_administrative_role_assignment",
                kwargs={"assignment_id": assignment.id},
            )
            for assignment in assignments
        ]
        self.perform_concurrent_requests("put", urls)


class AdministrativeRoleAssignmentTests(AdministrativeAccessTestCase):
    def test_assignment_create_detail_update_and_delete(self):
        self.client.force_authenticate(user=self.superuser)
        url = reverse("admin_administrative_role_assignment")
        response = self.client.post(
            url,
            {
                "role_id": str(self.role.id),
                "user_id": str(self.user_a.id),
                "is_global": False,
                "tenant_ids": [str(self.tenant_a.id)],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        assignment = models.AdministrativeRoleAssignment.objects.get(user=self.user_a)
        detail = reverse(
            "admin_administrative_role_assignment",
            kwargs={"assignment_id": assignment.id},
        )
        self.assertEqual(self.client.get(detail).status_code, status.HTTP_200_OK)
        response = self.client.put(detail, {"tenant_ids": [str(self.tenant_b.id)]})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            list(assignment.tenants.values_list("tenant_id", flat=True)),
            [self.tenant_b.id],
        )
        response = self.client.put(detail, {"is_global": True, "tenant_ids": []})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assignment.refresh_from_db()
        self.assertTrue(assignment.is_global)
        self.assertFalse(assignment.tenants.exists())
        self.assertEqual(self.client.delete(detail).status_code, status.HTTP_200_OK)
        self.assertFalse(
            models.AdministrativeRoleAssignment.objects.filter(
                pk=assignment.id
            ).exists()
        )
        self.assertFalse(
            models.AdministrativeRoleAssignmentTenant.objects.filter(
                assignment_id=assignment.id
            ).exists()
        )

    def test_assignment_requires_role_and_user(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(reverse("admin_administrative_role_assignment"), {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("ROLE_AND_USER_REQUIRED", response.data["non_field_errors"])

    def test_assignment_rejects_missing_role(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_administrative_role_assignment"),
            {
                "role_id": str(uuid4()),
                "user_id": str(self.user_a.id),
                "tenant_ids": [str(self.tenant_a.id)],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("NO_PERMISSION_OR_NOT_EXIST", response.data["non_field_errors"])

    def test_assignment_rejects_missing_user(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_administrative_role_assignment"),
            {
                "role_id": str(self.role.id),
                "user_id": str(uuid4()),
                "tenant_ids": [str(self.tenant_a.id)],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("NO_PERMISSION_OR_NOT_EXIST", response.data["non_field_errors"])

    def test_assignment_rejects_missing_tenant(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_administrative_role_assignment"),
            {
                "role_id": str(self.role.id),
                "user_id": str(self.user_a.id),
                "tenant_ids": [str(uuid4())],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("TENANT_NOT_EXIST", response.data["non_field_errors"])

    def test_assignment_rejects_duplicate_tenant(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_administrative_role_assignment"),
            {
                "role_id": str(self.role.id),
                "user_id": str(self.user_a.id),
                "tenant_ids": [str(self.tenant_a.id)] * 2,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("DUPLICATE_TENANT", response.data["non_field_errors"])

    def test_scoped_assignment_requires_tenant(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_administrative_role_assignment"),
            {
                "role_id": str(self.role.id),
                "user_id": str(self.user_a.id),
                "tenant_ids": [],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("TENANT_REQUIRED", response.data["non_field_errors"])

    def test_global_assignment_rejects_tenants(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            reverse("admin_administrative_role_assignment"),
            {
                "role_id": str(self.role.id),
                "user_id": str(self.user_a.id),
                "tenant_ids": [str(self.tenant_a.id)],
                "is_global": True,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(
            "GLOBAL_ASSIGNMENT_HAS_TENANTS", response.data["non_field_errors"]
        )

    def test_full_administrator_assignment_requires_global_scope(self):
        self.client.force_authenticate(user=self.superuser)
        full = models.AdministrativeRole.objects.get(system_key="full_administrator")
        response = self.client.post(
            reverse("admin_administrative_role_assignment"),
            {
                "role_id": str(full.id),
                "user_id": str(self.user_a.id),
                "tenant_ids": [str(self.tenant_a.id)],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_fileserver_administrator_assignment_requires_global_scope(self):
        self.client.force_authenticate(user=self.superuser)
        fileservers = models.AdministrativeRole.objects.get(
            system_key="fileserver_administrator"
        )
        response = self.client.post(
            reverse("admin_administrative_role_assignment"),
            {
                "role_id": str(fileservers.id),
                "user_id": str(self.user_a.id),
                "tenant_ids": [str(self.tenant_a.id)],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_assignment_detail_rejects_missing_assignment(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        detail = reverse(
            "admin_administrative_role_assignment", kwargs={"assignment_id": uuid4()}
        )
        self.assertEqual(
            self.client.get(detail).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_assignment_update_rejects_missing_assignment(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        detail = reverse(
            "admin_administrative_role_assignment", kwargs={"assignment_id": uuid4()}
        )
        self.assertEqual(
            self.client.put(detail).status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertFalse(
            models.AdministrativeRoleAssignment.objects.filter(
                user=self.user_a
            ).exists()
        )

    def test_assignment_delete_rejects_missing_assignment(self):
        from uuid import uuid4

        self.client.force_authenticate(user=self.superuser)
        detail = reverse(
            "admin_administrative_role_assignment", kwargs={"assignment_id": uuid4()}
        )
        self.assertEqual(
            self.client.delete(detail).status_code, status.HTTP_400_BAD_REQUEST
        )

    def test_assignment_list_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(reverse("admin_administrative_role_assignment"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_assignment_detail_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.get(
            reverse(
                "admin_administrative_role_assignment",
                kwargs={"assignment_id": self.assignment.id},
            )
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_assignment_creation_is_superuser_only(self):
        data = {
            "role_id": self.role.id,
            "user_id": self.user_a.id,
            "is_global": False,
            "tenant_ids": [self.tenant_a.id],
        }
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.post(
            reverse("admin_administrative_role_assignment"), data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(
            models.AdministrativeRoleAssignment.objects.filter(
                user=self.user_a
            ).exists()
        )

    def test_assignment_update_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.put(
            reverse(
                "admin_administrative_role_assignment",
                kwargs={"assignment_id": self.assignment.id},
            ),
            {
                "role_id": self.role.id,
                "user_id": self.user_a.id,
                "is_global": False,
                "tenant_ids": [self.tenant_a.id],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assignment.refresh_from_db()
        self.assertEqual(self.assignment.user_id, self.delegated_admin.id)
        self.assertFalse(
            models.AdministrativeRoleAssignment.objects.filter(
                user=self.user_a
            ).exists()
        )

    def test_assignment_delete_is_superuser_only(self):
        self.client.force_authenticate(user=self.delegated_admin)
        response = self.client.delete(
            reverse(
                "admin_administrative_role_assignment",
                kwargs={"assignment_id": self.assignment.id},
            )
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(
            models.AdministrativeRoleAssignment.objects.filter(
                pk=self.assignment.id
            ).exists()
        )

    def test_assignment_collision_validation_returns_bad_request(self):
        self.client.force_authenticate(user=self.superuser)
        second_role = models.AdministrativeRole.objects.create(name="Second Role")
        assignment_url = reverse("admin_administrative_role_assignment")
        assignment_data = {
            "role_id": self.role.id,
            "user_id": self.delegated_admin.id,
            "is_global": False,
            "tenant_ids": [self.tenant_a.id],
        }
        response = self.client.post(assignment_url, assignment_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        second_assignment = models.AdministrativeRoleAssignment.objects.create(
            role=second_role, user=self.delegated_admin, is_global=False
        )
        models.AdministrativeRoleAssignmentTenant.objects.create(
            assignment=second_assignment, tenant=self.tenant_a
        )
        response = self.client.put(
            reverse(
                "admin_administrative_role_assignment",
                kwargs={"assignment_id": second_assignment.id},
            ),
            assignment_data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_assignment_list_query_count_is_constant(self):
        second_role = models.AdministrativeRole.objects.create(name="Second Role")
        second_assignment = models.AdministrativeRoleAssignment.objects.create(
            role=second_role, user=self.user_a, is_global=False
        )
        models.AdministrativeRoleAssignmentTenant.objects.create(
            assignment=second_assignment, tenant=self.tenant_b
        )
        self.client.force_authenticate(user=self.superuser)

        with self.assertNumQueries(2):
            response = self.client.get(reverse("admin_administrative_role_assignment"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["assignments"]), 2)
