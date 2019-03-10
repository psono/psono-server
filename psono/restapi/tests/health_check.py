from django.urls import reverse

from rest_framework import status
from .base import APITestCaseExtended


class HealthCheckTest(APITestCaseExtended):
    """
    Test for health check
    """

    def test_put_healthcheck(self):
        """
        Tests PUT method on healthcheck
        """

        url = reverse('healthcheck')

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_post_healthcheck(self):
        """
        Tests POST method on healthcheck
        """

        url = reverse('healthcheck')

        data = {}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_healthcheck(self):
        """
        Tests DELETE method on healthcheck
        """

        url = reverse('healthcheck')

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_get_healthcheck(self):
        """
        Tests GET method on
        """

        url = reverse('healthcheck')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

