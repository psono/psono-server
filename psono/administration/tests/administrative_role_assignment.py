from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase


class AdministrativeRoleAssignmentTests(AdministrativeAccessTestCase):
    def test_all_administrative_role_assignment_methods_are_superuser_only(self):
        detail_url = reverse(
            "admin_administrative_role_assignment",
            kwargs={"assignment_id": self.assignment.id},
        )
        data = {
            "role_id": self.role.id,
            "user_id": self.user_a.id,
            "is_global": False,
            "tenant_ids": [self.tenant_a.id],
        }
        requests = (
            ("get", reverse("admin_administrative_role_assignment"), None),
            ("get", detail_url, None),
            ("post", reverse("admin_administrative_role_assignment"), data),
            ("put", detail_url, data),
            ("delete", detail_url, None),
        )
        self.client.force_authenticate(user=self.delegated_admin)

        for method, url, request_data in requests:
            with self.subTest(method=method, url=url):
                response = getattr(self.client, method)(url, request_data or {})
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.assertTrue(
            models.AdministrativeRoleAssignment.objects.filter(
                pk=self.assignment.id
            ).exists()
        )
        self.assertFalse(
            models.AdministrativeRoleAssignment.objects.filter(
                user=self.user_a
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
