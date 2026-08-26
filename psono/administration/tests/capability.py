from django.urls import reverse
from rest_framework import status

from .helpers import AdministrativeAccessTestCase


class AdministrativeCapabilityTests(AdministrativeAccessTestCase):
    def test_unusable_management_capabilities_are_not_advertised(self):
        self.client.force_authenticate(user=self.superuser)

        response = self.client.get(reverse("admin_capability"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        codes = {item["code"] for item in response.data["capabilities"]}
        self.assertNotIn("tenants.manage", codes)
        self.assertNotIn("admin_roles.manage", codes)
        descriptions = {
            item["code"]: item["description"] for item in response.data["capabilities"]
        }
        self.assertEqual(
            descriptions["groups.shares.manage"], "MANAGE_GROUP_SHARE_RIGHTS"
        )
