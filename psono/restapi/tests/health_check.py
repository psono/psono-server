from django.core.urlresolvers import reverse
from django.contrib.auth.hashers import make_password

from rest_framework import status
from .base import APITestCaseExtended

from restapi import models


class HealthCheckTest(APITestCaseExtended):
    """
    Test for health check
    """

    def test_put_healthcheckn(self):
        """
        Tests PUT method on healthcheck
        """

        url = reverse('healthcheck')

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_post_healthcheckn(self):
        """
        Tests POST method on healthcheck
        """

        url = reverse('healthcheck')

        data = {}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_healthcheckn(self):
        """
        Tests DELETE method on healthcheck
        """

        url = reverse('healthcheck')

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_get_healthcheckn(self):
        """
        Tests GET method on healthcheck
        """

        url = reverse('healthcheck')

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

