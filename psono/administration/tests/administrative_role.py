from django.urls import reverse
from rest_framework import status
from restapi import models

from .helpers import AdministrativeAccessTestCase


class AdministrativeRoleTests(AdministrativeAccessTestCase):
    def test_all_administrative_role_methods_are_superuser_only(self):
        detail_url = reverse(
            "admin_administrative_role", kwargs={"role_id": self.role.id}
        )
        requests = (
            ("get", reverse("admin_administrative_role"), None),
            ("get", detail_url, None),
            (
                "post",
                reverse("admin_administrative_role"),
                {"name": "Forbidden Role"},
            ),
            ("put", detail_url, {"name": "Forbidden Update"}),
            ("delete", detail_url, None),
        )
        self.client.force_authenticate(user=self.delegated_admin)

        for method, url, data in requests:
            with self.subTest(method=method, url=url):
                response = getattr(self.client, method)(url, data or {})
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.role.refresh_from_db()
        self.assertEqual(self.role.name, "Tenant User Reader")
        self.assertFalse(
            models.AdministrativeRole.objects.filter(name="Forbidden Role").exists()
        )

    def test_default_roles_have_stable_capability_bundles(self):
        expected = {
            "full_administrator": None,
            "user_administrator": {
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
            "group_administrator": {
                "groups.read",
                "groups.update",
                "groups.delete",
                "groups.memberships.read",
                "groups.memberships.manage",
                "groups.shares.manage",
            },
            "read_only_auditor": {
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
            "fileserver_administrator": {
                "fileservers.read",
                "fileservers.manage",
            },
        }

        roles = models.AdministrativeRole.objects.filter(
            is_system=True
        ).prefetch_related("capabilities")

        self.assertEqual({role.system_key for role in roles}, set(expected))
        for role in roles:
            self.assertEqual(role.is_full_access, expected[role.system_key] is None)
            self.assertEqual(
                {item.capability for item in role.capabilities.all()},
                expected[role.system_key] or set(),
            )

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
