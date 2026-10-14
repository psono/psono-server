from contextlib import redirect_stdout
from io import StringIO

from django.urls import reverse
from django.test import override_settings
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.recorder import MigrationRecorder
from types import SimpleNamespace
from unittest.mock import patch

from rest_framework import status
from rest_framework.test import APITransactionTestCase
from .base import APITestCaseExtended


class HealthCheckTest(APITestCaseExtended):
    """
    Test for health check
    """

    def test_put_healthcheck(self):
        """
        Tests PUT method on healthcheck
        """

        url = reverse("healthcheck")

        data = {}

        response = self.client.put(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_post_healthcheck(self):
        """
        Tests POST method on healthcheck
        """

        url = reverse("healthcheck")

        data = {}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_healthcheck(self):
        """
        Tests DELETE method on healthcheck
        """

        url = reverse("healthcheck")

        data = {}

        response = self.client.delete(url, data)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch(
        "restapi.views.health_check.ntplib.NTPClient.request",
        return_value=SimpleNamespace(offset=0),
    )
    def test_get_healthcheck(self, ntp_request):
        """
        Tests GET method on
        """

        url = reverse("healthcheck")

        data = {}

        response = self.client.get(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(HEALTHCHECK_TIME_SYNC_ENABLED=True)
    def test_clock_drift_reports_unhealthy(self):
        with patch(
            "restapi.views.health_check.ntplib.NTPClient.request",
            return_value=SimpleNamespace(offset=2),
        ):
            with redirect_stdout(StringIO()):
                result = self.client.get(reverse("healthcheck"))
        self.assertEqual(result.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(result.data["time_sync"]["healthy"])
        self.assertTrue(result.data["db_read"]["healthy"])

    @override_settings(HEALTHCHECK_TIME_SYNC_ENABLED=True)
    def test_ntp_outage_reports_unhealthy(self):
        with patch(
            "restapi.views.health_check.ntplib.NTPClient.request",
            side_effect=OSError("NTP unavailable"),
        ):
            with redirect_stdout(StringIO()):
                result = self.client.get(reverse("healthcheck"))
        self.assertEqual(result.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(result.data["time_sync"]["healthy"])
        self.assertTrue(result.data["db_read"]["healthy"])

    @override_settings(HEALTHCHECK_TIME_SYNC_ENABLED=False)
    def test_unapplied_migration_is_detected_from_real_database_state(self):
        app, name = MigrationExecutor(connection).loader.graph.leaf_nodes("restapi")[0]
        recorder = MigrationRecorder(connection)
        recorder.record_unapplied(app, name)
        try:
            with redirect_stdout(StringIO()):
                response = self.client.get(reverse("healthcheck"))
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertTrue(response.data["db_read"]["healthy"])
            self.assertFalse(response.data["db_sync"]["healthy"])
        finally:
            recorder.record_applied(app, name)


@override_settings(HEALTHCHECK_TIME_SYNC_ENABLED=False)
class HealthCheckDatabaseDisconnectTest(APITransactionTestCase):
    def test_real_database_connection_failure_is_reported(self):
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            backend_pid = cursor.fetchone()[0]
        controller = connection.copy(alias="healthcheck-controller")
        try:
            with controller.cursor() as cursor:
                cursor.execute("SELECT pg_terminate_backend(%s)", [backend_pid])
                self.assertTrue(cursor.fetchone()[0])
            with redirect_stdout(StringIO()):
                response = self.client.get(reverse("healthcheck"))
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertFalse(response.data["db_read"]["healthy"])
            self.assertFalse(response.data["db_sync"]["healthy"])
        finally:
            connection.close()
            controller.close()
