import binascii
import json

from django.conf import settings
from django.urls import reverse
import nacl.encoding
import nacl.signing
from rest_framework import status

from .base import APITestCaseExtended


class ReadInfoTest(APITestCaseExtended):
    """
    Test to read info ressource
    """

    def test_read_info_success(self):
        """
        Tests to read the public server info
        """

        url = reverse("info")

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("verify_key", None), None)
        self.assertNotEqual(response.data.get("info", None), None)
        self.assertNotEqual(response.data.get("signature", None), None)

        info = json.loads(response.data.get("info"))

        self.assertNotEqual(info.get("web_client", None), None)
        self.assertNotEqual(info.get("version", None), None)
        self.assertNotEqual(info.get("log_audit", None), None)
        self.assertNotEqual(info.get("public_key", None), None)
        self.assertIn("admin_recovery_public_key", info)
        self.assertNotEqual(info.get("api", None), None)
        self.assertNotEqual(info.get("authentication_methods", None), None)
        self.assertNotEqual(info.get("management", None), None)

        self.assertEqual(info.get("version", None), settings.VERSION)
        self.assertEqual(info.get("public_key", None), settings.PUBLIC_KEY)
        self.assertEqual(
            info.get("admin_recovery_public_key"),
            settings.ADMIN_RECOVERY_PUBLIC_KEY,
        )
        self.assertEqual(
            info.get("authentication_methods", None), settings.AUTHENTICATION_METHODS
        )
        self.assertEqual(info.get("management", None), settings.MANAGEMENT_ENABLED)

        verify_key = nacl.signing.VerifyKey(
            response.data["verify_key"], encoder=nacl.encoding.HexEncoder
        )
        verify_key.verify(
            response.data["info"].encode(),
            binascii.unhexlify(response.data["signature"]),
        )

    def test_put_info(self):
        """
        Tests PUT request on info
        """

        url = reverse("info")

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_post_info(self):
        """
        Tests POST request on info
        """

        url = reverse("info")

        data = {}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_info(self):
        """
        Tests DELETE request on info
        """

        url = reverse("info")

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
