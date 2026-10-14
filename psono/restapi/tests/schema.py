from contextlib import redirect_stderr
from importlib import reload
from io import StringIO

from django.urls import clear_url_caches, reverse
from rest_framework import status

from .base import APITestCaseExtended


class SchemaViewTests(APITestCaseExtended):
    def test_debug_schema_describes_supported_endpoint_operations(self):
        from psono import urls

        diagnostics = StringIO()
        try:
            # Keep optional schema diagnostics available on failure without
            # flooding successful application test runs with metadata warnings.
            with redirect_stderr(diagnostics):
                try:
                    with self.settings(DEBUG=True):
                        reload(urls)
                        clear_url_caches()
                        response = self.client.get(
                            reverse("schema"),
                            HTTP_ACCEPT="application/vnd.oai.openapi+json",
                        )
                finally:
                    reload(urls)
                    clear_url_caches()

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            paths = response.data["paths"]
            self.assertIn("get", paths["/share/"])
            self.assertIn("put", paths["/share/"])
            self.assertIn("post", paths["/share/"])
            self.assertIn("delete", paths["/admin/user/"])
            self.assertIn("put", paths["/admin/group/"])
            self.assertIn("delete", paths["/admin/group/"])
            self.assertIn("put", paths["/admin/membership/"])
            self.assertIn("delete", paths["/admin/membership/"])
            self.assertIn("put", paths["/fileserver/upload/authorize/"])
            self.assertEqual(
                paths["/user/webauthn/"]["post"]["requestBody"]["content"][
                    "application/json"
                ]["schema"]["$ref"],
                "#/components/schemas/ActivateWebauthn",
            )
            self.assertEqual(
                paths["/link-share-access/"]["put"]["requestBody"]["content"][
                    "application/json"
                ]["schema"]["$ref"],
                "#/components/schemas/UpdateLinkShareAccess",
            )
            self.assertEqual(
                paths["/password/"]["post"]["requestBody"]["content"][
                    "application/json"
                ]["schema"]["$ref"],
                "#/components/schemas/EnableNewPassword",
            )
            self.assertEqual(
                response.data["components"]["schemas"]["UpdateLinkShare"]["properties"][
                    "allow_write"
                ]["type"],
                "boolean",
            )
        except Exception as error:
            error.add_note("OpenAPI schema diagnostics:\n" + diagnostics.getvalue())
            raise
