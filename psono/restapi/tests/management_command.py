from django.urls import reverse

from rest_framework import status
from .base import APITestCaseExtended
from rest_framework.test import APIClient
from django.test.utils import override_settings
from restapi import models


MANAGEMENT_COMMAND_ACCESS_KEY = 'ABC'

class ManagementCommandTest(APITestCaseExtended):
    """
    Test to execute a management command remote
    """

    @override_settings(MANAGEMENT_COMMAND_ACCESS_KEY=MANAGEMENT_COMMAND_ACCESS_KEY)
    def test_command_without_args(self):
        """
        Tests to execute a command that does not need args
        """


        url = reverse('management_command')

        data = {
            'command_name': 'cleartoken',
        }

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + MANAGEMENT_COMMAND_ACCESS_KEY)

        response = client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(MANAGEMENT_COMMAND_ACCESS_KEY=MANAGEMENT_COMMAND_ACCESS_KEY)
    def test_command_with_wrong_access_key(self):
        """
        Tests to execute a command with wrong access key
        """
        url = reverse('management_command')

        data = {
            'command_name': 'cleartoken',
        }

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + MANAGEMENT_COMMAND_ACCESS_KEY + 'abcd')

        response = client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @override_settings(MANAGEMENT_COMMAND_ACCESS_KEY='')
    def test_command_with_unconfigured_access_key(self):
        """
        Tests to execute a command but noone configured a management command access key
        """
        url = reverse('management_command')

        data = {
            'command_name': 'cleartoken',
        }

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + '')

        response = client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @override_settings(MANAGEMENT_COMMAND_ACCESS_KEY=MANAGEMENT_COMMAND_ACCESS_KEY)
    def test_command_with_args(self):
        """
        Tests to execute a command but noone configured a management command access key
        """
        url = reverse('management_command')

        username = 'demo@example.com'
        password = 'demo'
        email = 'demo@example.com'
        data = {
            'command_name': 'createuser',
            'command_args': [username, password, email],
        }

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + MANAGEMENT_COMMAND_ACCESS_KEY)

        response = client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(models.User.objects.filter(username=username).exists())
